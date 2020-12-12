<?php

namespace App\Repositories;

use App\Http\Resources\InviteeCollection;
use App\Models\Invitee;
use App\Models\Meeting;
use App\Models\User;
use App\Notifications\MeetingInvitation;
use App\Repositories\ContactRepository;
use App\Repositories\MeetingRepository;
use App\Repositories\SegmentRepository;
use Illuminate\Support\Arr;
use Illuminate\Validation\UnauthorizedException;
use Illuminate\Validation\ValidationException;

class InviteeRepository
{
    protected $meeting;
    protected $invitee;
    protected $segment;
    protected $contact;

    /**
     * Instantiate a new instance
     * @return void
     */
    public function __construct(
        MeetingRepository $meeting,
        Invitee $invitee,
        SegmentRepository $segment,
        ContactRepository $contact
    ) {
        $this->meeting = $meeting;
        $this->invitee = $invitee;
        $this->segment = $segment;
        $this->contact = $contact;
    }

    /**
     * Get pre requisites
     */
    public function getPreRequisite() : array
    {
        $segments = $this->segment->getAll();
        $contacts = $this->contact->getAll();

        return compact('segments', 'contacts');
    }

    /**
     * Get meeting invitee
     *
     * @param Meeting $meeting
     */
    public function getInvitees(Meeting $meeting) : InviteeCollection
    {
        $meeting->isAccessible();

        $sort_by = request()->query('sort_by', 'created_at');
        $order   = request()->query('order', 'desc');

        $per_page     = request('per_page', config('config.system.per_page'));
        $current_page = request('current_page');

        return new InviteeCollection($this->invitee->whereMeetingId($meeting->id)->orderBy($sort_by, $order)->paginate((int) $per_page, ['*'], 'current_page'));
    }

    /**
     * Add meeting invitee
     *
     * @param Meeting $meeting
     */
    public function addInvitees(Meeting $meeting) : void
    {
        $meeting->ensureIsScheduled();

        $meeting->isAccessible(true);

        $contact_uuids = collect(request('contacts', []))->pluck('uuid')->all();
        $segment_uuids = collect(request('segments', []))->pluck('uuid')->all();

        $contacts = $this->contact->filterByUuids($contact_uuids);
        $segments = $this->segment->filterByUuids($segment_uuids);

        $invitees = $contacts->pluck('id')->all();
        foreach ($segments as $segment) {
            $invitees = array_merge($invitees, $segment->contacts()->pluck('id')->all());
        }
        
        $invitees = array_unique($invitees);

        foreach ($invitees as $invitee) {
            $this->invitee->create([
                'meeting_id' => $meeting->id,
                'contact_id' => $invitee
            ]);
        }
    }

    /**
     * Send meeting invitation
     *
     * @param Meeting $meeting
     */
    public function sendInvitation(Meeting $meeting) : void
    {
        $meeting->ensureIsScheduled();

        $meeting->isAccessible(true);
        
        $invitee_uuid = Arr::get(request('invitee', []), 'uuid');
        $invitees = $this->invitee->whereMeetingId($meeting->id)
            ->when($invitee_uuid, function ($q, $invitee_uuid) {
                return $q->whereUuid($invitee_uuid);
            })->get();

        foreach ($invitees as $invitee) {
            (new User)->forceFill([
                'email' => $invitee->contact->email,
            ])->notify(new MeetingInvitation($meeting, $invitee->contact));
        }
    }

    /**
     * Toggle meeting moderator
     *
     * @param Meeting $meeting
     */
    public function toggleModerator(Meeting $meeting) : void
    {
        $meeting->ensureIsScheduled();

        $invitee_uuid = Arr::get(request('invitee', []), 'uuid');
        $invitee = $this->invitee->whereMeetingId($meeting->id)->whereUuid($invitee_uuid)->first();

        if (! $invitee) {
            throw ValidationException::withMessages(['message' => __('global.could_not_find', ['attribute' => __('meeting.invitee.invtee')])]);
        }

        $meta = $invitee->meta;
        $meta['is_moderator'] = ! $invitee->getMeta('is_moderator');
        $invitee->meta = $meta;
        $invitee->save();
    }

    /**
     * Join meeting
     *
     * @param Meeting $meeting
     */
    public function join(Meeting $meeting) : Meeting
    {
        if ($meeting->user_id === \Auth::user()->id) {
            $meeting->live();

            return $meeting->logAdmin();
        }

        $invitee = $meeting->getInvitee();

        if ($invitee->getMeta('is_moderator')) {
            $meeting->live();
        } else {
            $meeting->ensureIsLive();
        }

        $invitee->logInvitee();

        return $meeting;
    }

    /**
     * Leave meeting
     *
     * @param Meeting $meeting
     */
    public function leave(Meeting $meeting) : Meeting
    {
        $meeting->ensureIsLive();

        if ($meeting->user_id === \Auth::user()->id) {
            return $meeting;
        }

        $invitee = $meeting->getInvitee();

        $invitee->logError();

        return $meeting;
    }

    /**
     * End meeting
     *
     * @param Meeting $meeting
     */
    public function end(Meeting $meeting) : Meeting
    {
        $meeting->ensureIsLive();

        if ($meeting->user_id === \Auth::user()->id) {
            return $meeting->end();
        }

        $invitee = $meeting->getInvitee();

        if ($invitee->getMeta('is_moderator')) {
            return $meeting->end();
        }

        return $meeting;
    }

    /**
     * Delete meeting invitee
     *
     * @param Meeting $meeting
     * @param uuid $invitee_uuid
     */
    public function deleteInvitee(Meeting $meeting, $invitee_uuid) : void
    {
        $meeting->ensureIsScheduled();

        $invitee = $this->invitee->whereMeetingId($meeting->id)->whereUuid($invitee_uuid)->first();

        if (! $invitee) {
            throw ValidationException::withMessages(['message' => __('global.could_not_find', ['attributes' => __('meeting.invitee')])]);
        }

        $invitee->delete();
    }
}
