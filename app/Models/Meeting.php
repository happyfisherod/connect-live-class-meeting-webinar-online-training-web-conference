<?php

namespace App\Models;

use App\Enums\MeetingStatus;
use App\Events\MeetingStatusChanged;
use App\Helpers\CalHelper;
use App\Helpers\IpHelper;
use App\Traits\HasMeta;
use App\Traits\HasUuid;
use App\Models\User;
use App\Models\Option;
use App\Traits\ModelOption;
use Carbon\Carbon;
use Illuminate\Support\Str;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Support\Arr;
use Illuminate\Validation\UnauthorizedException;
use Illuminate\Validation\ValidationException;
use Spatie\Activitylog\Traits\LogsActivity;
use Spatie\MediaLibrary\HasMedia;
use Spatie\MediaLibrary\InteractsWithMedia;

class Meeting extends Model implements HasMedia
{
    use HasMeta, HasUuid, ModelOption, InteractsWithMedia, LogsActivity;

    protected $guarded = [];
    protected $casts = [
        'meta' => 'array',
        'start_date_time' => 'datetime'
    ];
    protected $table = 'meetings';
    protected static $logName = 'meeting';
    protected static $logFillable = ['*'];
    protected static $logOnlyDirty = true;
    protected static $logAttributesToIgnore = [ 'updated_at'];
    protected $with = ['user', 'category'];
    protected static $sortOptions = ['created_at', 'keyword', 'start_date_time'];
    protected static $defaultSortBy = 'start_date_time';

    // Relations
    public function user() : BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    public function category() : BelongsTo
    {
        return $this->belongsTo(Option::class, 'category_id');
    }

    public function invitees() : HasMany
    {
        return $this->hasMany(Invitee::class);
    }

    public function comments()
    {
        return $this->morphMany(Comment::class, 'commentable');
    }

    // Booted
    public static function booted()
    {
    }

    // Attributes
    public function getPlannedStartDateTimeAttribute()
    {
        $snoozed_logs = $this->getMeta('snoozed_logs') ? : [];

        if (! $snoozed_logs) {
            return $this->start_date_time;
        }

        return Arr::get(Arr::first($snoozed_logs), 'start_date_time');
    }

    // Constrains

    public function ensureNotCancelled() : void
    {
        if ($this->getMeta('status') === MeetingStatus::CANCELLED) {
            throw ValidationException::withMessages(['message' => __('meeting.invalid_action_with_status', ['attribute' => trans('meeting.status.'. $this->getMeta('status'))])]);
        }
    }

    public function ensureIsLive() : void
    {
        if ($this->getMeta('status') != MeetingStatus::LIVE) {
            throw ValidationException::withMessages(['message' => __('meeting.invalid_action_with_status', ['attribute' => trans('meeting.status.'. $this->getMeta('status'))])]);
        }
    }

    public function ensureIsScheduled() : void
    {
        if ($this->getMeta('status') != MeetingStatus::SCHEDULED) {
            throw ValidationException::withMessages(['message' => __('meeting.invalid_action_with_status', ['attribute' => trans('meeting.status.'. $this->getMeta('status'))])]);
        }
    }

    public function ensureIsScheduledOrLive() : void
    {
        if (! in_array($this->getMeta('status'), [MeetingStatus::SCHEDULED, MeetingStatus::LIVE])) {
            throw ValidationException::withMessages(['message' => __('meeting.invalid_action_with_status', ['attribute' => trans('meeting.status.'. $this->getMeta('status'))])]);
        }
    }

    public function ensureCommentable() : void
    {
        $this->isAccessible();

        $config = $this->getMeta('config') ? : [];

        if (! Arr::get($config, 'enable_comments')) {
            throw new UnauthorizedException();
        }

        if (! Arr::get($config, 'enable_comment_before_meeting_starts') && $this->getMeta('status') === MeetingStatus::SCHEDULED) {
            throw new UnauthorizedException();
        }

        $this->ensureIsScheduledOrLive();
    }

    public function isAccessible($editable = false) : bool
    {
        if (\Auth::user()->id === $this->user_id) {
            return true;
        }
        
        $invitee = $this->getInvitee();

        if ($editable && ! $invitee->getMeta('is_moderator')) {
            return false;
        }

        return true;
    }

    public function getInvitee() : ?Invitee
    {
        if (! $this->relationLoaded('invitees')) {
            $this->load(['invitees']);
        }

        $contact = \Auth::user()->contact;

        if (! $contact) {
            throw new UnauthorizedException();
        }

        $invitee = $this->invitees()->firstWhere('contact_id', $contact->id);

        if (! $invitee) {
            throw new UnauthorizedException();
        }

        return $invitee;
    }

    // Actions

    public function isCancellable() : self
    {
        if ($this->getMeta('status') != MeetingStatus::SCHEDULED) {
            return $this;
        }
        
        $date = Carbon::parse($this->start_date_time);

        if ($date->isFuture()) {
            return $this;
        }

        if ($date->diffInMinutes(now()) < 60) {
            return $this;
        }

        $meta = $this->meta;
        $meta['status'] = MeetingStatus::CANCELLED;
        $meta['cancellation_reason'] = 'auto';
        $meta['cancelled_at'] = now();
        $this->meta = $meta;
        $this->save();

        broadcast(new MeetingStatusChanged($this))->toOthers();

        return $this;
    }

    public function cancel() : self
    {
        $meta = $this->meta;
        $meta['status'] = MeetingStatus::CANCELLED;
        $meta['cancellation_reason'] = request('cancellation_reason');
        $meta['cancelled_at'] = now();
        $this->meta = $meta;
        $this->save();

        broadcast(new MeetingStatusChanged($this))->toOthers();

        return $this;
    }

    public function config() : self
    {
        $meta = $this->meta;
        $config = $meta['config'] ?? [];
        $config['enable_comments'] = request()->boolean('enable_comments');
        $config['private_comments'] = request()->boolean('private_comments');
        $config['enable_comment_before_meeting_starts'] = request()->boolean('enable_comment_before_meeting_starts');
        $meta['config'] = $config;
        $this->meta = $meta;
        $this->save();

        return $this;
    }

    public function snooze() : self
    {
        $meta = $this->meta;
        $snoozed_logs = $meta['snoozed_logs'] ?? [];
        array_push($snoozed_logs, array(
            'start_date_time' => $this->start_date_time,
            'period' => request('period')
        ));

        $meta['snoozed_logs'] = $snoozed_logs;
        $this->meta = $meta;

        if (Carbon::parse($this->start_date_time)->isFuture()) {
            $this->start_date_time = Carbon::parse($this->start_date_time)->addMinutes(request('period'));
        } else {
            $this->start_date_time = Carbon::parse(now())->addMinutes(request('period'));
        }
        
        $this->save();

        broadcast(new MeetingStatusChanged($this))->toOthers();

        return $this;
    }

    public function live() : self
    {
        if ($this->getMeta('status') === MeetingStatus::LIVE) {
            return $this;
        }

        $meta = $this->meta;
        $meta['status'] = MeetingStatus::LIVE;
        $meta['room_id'] = Str::random(20);
        $meta['started_at'] = now();
        $this->meta = $meta;
        $this->save();
        broadcast(new MeetingStatusChanged($this))->toOthers();

        return $this;
    }

    public function end() : self
    {
        $meta = $this->meta;
        $meta['status'] = MeetingStatus::ENDED;
        $meta['ended_at'] = now();
        $this->meta = $meta;
        $this->save();
        broadcast(new MeetingStatusChanged($this))->toOthers();

        return $this;
    }

    public function logAdmin() : self
    {
        $meta = $this->meta;
        $meta['is_attendee'] = true;
        $logs = $meta['logs'] ?? [];
        array_push($logs, array(
            'start' => now(),
            'ip' => IpHelper::getClientIp()
        ));

        $meta['logs'] = $logs;
        $this->meta = $meta;
        $this->save();

        return $this;
    }

    // Filters

    public function scopeMyMeeting(Builder $query) : void
    {
        $query->where(function($q) {
            $q->whereUserId(\Auth::user()->id)
            ->orWhereHas('invitees', function($q1) {
                $q1->whereHas('contact', function($q2) {
                    $q2->whereUserId(\Auth::user()->id);
                });
            });
        });
    }

    public function scopeIsNotCancelled(Builder $query) : void
    {
        $query->where('meta->status', '!=', 'cancelled');
    }

    public function scopeIsScheduled(Builder $query) : void
    {
        $query->where('meta->status', '=', 'scheduled');
    }

    public function scopeattendedMeeting(Builder $query) : void
    {
        $query->where(function($q) {
            $q->where(function($q0) {
                $q0->whereUserId(\Auth::user()->id)->where('meta->is_attendee', \Auth::user()->id);
            })->orWhereHas('invitees', function($q1) {
                $q1->where('is_attendee', 1);
            });
        });
    }

    public function scopeFilterByKeyword(Builder $query, $keyword = null) : void
    {
        $query->when($keyword, function ($q, $keyword) {
            return $q->where(function ($q1) use ($keyword) {
                $q1->where('title', 'like', '%'.$keyword.'%')->orWhere('agenda', 'like', '%'.$keyword.'%')->orWhere('description', 'like', '%'.$keyword.'%');
            });
        });
    }

    public function scopeDateBetween(Builder $query, $dates) : void
    {
        $start_date = Arr::get($dates, 'start_date');
        $end_date = Arr::get($dates, 'end_date') ? : $start_date;

        if ($start_date && $end_date && $start_date <= $end_date) {
            $query->where('start_date_time', '>=', CalHelper::startOfDate($start_date))->where('start_date_time', '<=', CalHelper::endOfDate($end_date));
        }
    }

    public function scopeFilterByName(Builder $query, $name = null) : void
    {
        $query->when($name, function ($q, $name) {
            return $q->where('name', 'like', '%'.$name.'%');
        });
    }
}
