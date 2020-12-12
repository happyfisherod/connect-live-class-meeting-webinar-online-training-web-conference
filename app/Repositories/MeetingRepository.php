<?php

namespace App\Repositories;

use App\Enums\MeetingStatus;
use App\Helpers\ArrHelper;
use App\Models\Meeting;
use App\Http\Resources\MeetingCollection;
use App\Repositories\OptionRepository;
use Illuminate\Support\Arr;
use Illuminate\Validation\ValidationException;

class MeetingRepository
{
    protected $meeting;
    protected $option;

    /**
     * Instantiate a new instance
     * @return void
     */
    public function __construct(
        Meeting $meeting,
        OptionRepository $option
    ) {
        $this->meeting = $meeting;
        $this->option = $option;
    }

    /**
     * Find meeting with given id or throw an error
     * @param integer $id
     */
    public function findOrFail($id, $field = 'message') : Meeting
    {
        $meeting = $this->meeting->find($id);

        if (! $meeting) {
            throw ValidationException::withMessages([$field => __('global.could_not_find', ['attribute' => __('meeting.meeting')])]);
        }

        return $meeting;
    }

    /**
     * Find meeting with given uuid or throw an error
     * @param uuid $uuid
     */
    public function findByUuidOrFail($uuid, $field = 'message') : Meeting
    {
        $meeting = $this->meeting->filterByUuid($uuid)->first();

        if (! $meeting) {
            throw ValidationException::withMessages([$field => __('global.could_not_find', ['attribute' => __('contact.meeting.meeting')])]);
        }

        return $meeting;
    }

    /**
     * Paginate all meetings
     */
    public function paginate() : MeetingCollection
    {
        $sort_by = $this->meeting->getSortBy();
        $order   = $this->meeting->getOrder();
        $keyword = request()->query('keyword');

        $query = $this->meeting->filterByKeyword($keyword)->where(function ($q) {
            $q->whereUserId(\Auth::user()->id)->orWhere(function ($q1) {
                $contact = \Auth::user()->contact;
                $q1->when($contact, function ($q2, $contact) {
                    $q2->whereHas('invitees', function ($q3) use ($contact) {
                        $q3->where('contact_id', $contact->id);
                    });
                });
            });
        });

        $per_page     = request('per_page', config('config.system.per_page'));
        $current_page = request('current_page');

        return new MeetingCollection($query->orderBy($sort_by, $order)->paginate((int) $per_page, ['*'], 'current_page'));
    }

    /**
     * Get meeting pre requisite
     */
    public function getPreRequisite() : array
    {
        $categories = $this->option->listOrderedByName([ 'type' => 'meeting_category' ]);
        $types = ArrHelper::getTransList('types', 'meeting');

        return compact('categories', 'types');
    }

    /**
     * Create a new meeting
     */
    public function create() : Meeting
    {
        return $this->meeting->forceCreate($this->formatParams());
    }

    /**
     * Prepare given params for inserting into database
     * @param uuid $uuid
     */
    private function formatParams($uuid = null) : array
    {
        $type = Arr::get(request('type', []), 'uuid');

        $category = $this->option->findByUuidOrFail(Arr::get(request('category', []), 'uuid'));

        $formatted = [
            'title'           => request('title'),
            'type'            => $type,
            'category_id'     => $category->id,
            'agenda'          => request('agenda'),
            'description'     => request('description'),
            'start_date_time' => request('start_date_time'),
            'period'          => request('period'),
        ];

        if (! $uuid) {
            $formatted['meta'] = ['status' => MeetingStatus::SCHEDULED];
            $formatted['user_id'] = \Auth::user()->id;
        }

        return $formatted;
    }

    /**
     * Update given meeting
     * @param Meeting $meeting
     */
    public function update(Meeting $meeting) : Meeting
    {
        $meeting->ensureIsScheduled();

        $meeting->forceFill($this->formatParams($meeting->uuid))->save();

        return $meeting;
    }

    /**
     * Delete meeting
     * @param Meeting $meeting
     */
    public function delete(Meeting $meeting) : void
    {
        $meeting->ensureIsScheduled();
        
        $meeting->delete();
    }

    /**
     * Store meeting config
     *
     * @param Meeting $meeting
     */
    public function config(Meeting $meeting) : Meeting
    {
        $meeting->ensureIsScheduledOrLive();

        request()->validate([
            'enable_comments'  => 'boolean',
            'private_comments' => 'boolean',
            'enable_comment_before_meeting_starts' => 'boolean',
        ], [], [
            'enable_comments'  => __('meeting.config.enable_comments'),
            'private_comments' => __('meeting.config.private_comments'),
            'enable_comment_before_meeting_starts' => __('meeting.config.enable_comment_before_meeting_starts'),
        ]);

        return $meeting->config();
    }

    /**
     * Snooze meeting
     *
     * @param Meeting $meeting
     */
    public function snooze(Meeting $meeting) : Meeting
    {
        $meeting->ensureIsScheduled();

        request()->validate([
            'period' => 'required|integer|min:5|max:60'
        ], [], [
            'period' => __('meeting.props.period')
        ]);

        return $meeting->snooze();
    }

    /**
     * Cancel meeting
     *
     * @param Meeting $meeting
     */
    public function cancel(Meeting $meeting) : Meeting
    {
        $meeting->ensureIsScheduled();

        request()->validate([
            'cancellation_reason' => 'required'
        ], [], [
            'cancellation_reason' => __('meeting.props.cancellation_reason')
        ]);

        return $meeting->cancel();
    }
}
