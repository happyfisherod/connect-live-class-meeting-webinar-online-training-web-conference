<?php

namespace App\Http\Controllers;

use App\Http\Controllers\Controller;
use App\Http\Requests\ConnectRequest;
use App\Http\Requests\InviteRequest;
use App\Models\Meeting;
use App\Repositories\InviteeRepository;
use App\Http\Resources\Meeting as MeetingResource;

class InviteeController extends Controller
{
    protected $repo;

    /**
     * Instantiate a new instance
     * @return void
     */
    public function __construct(
        InviteeRepository $repo
    ) {
        $this->repo = $repo;
    }

    /**
     * Get meeting invitee pre requisite
     * @get ("/api/meetings/{meeting}/invitees/pre-requisite")
     * @return array
     */
    public function preRequisite()
    {
        return $this->ok($this->repo->getPreRequisite());
    }

    /**
     * Get meeting invitees
     * @get ("/api/meeting/{meeting}/invitees")
     * @return array
     */
    public function getInvitees(Meeting $meeting)
    {
        return $this->repo->getInvitees($meeting);
    }

    /**
     * Add meeting invitees
     * @get ("/api/meeting/{meeting}/invitees")
     * @return array
     */
    public function addInvitees(Meeting $meeting)
    {
        $this->repo->addInvitees($meeting);

        return $this->success(['message' => __('global.added', ['attribute' => __('meeting.invitee.invitee')])]);
    }

    /**
     * Send meeting invitation
     * @post ("/api/meeting/{meeting}/invitation")
     * @return array
     */
    public function sendInvitation(Meeting $meeting)
    {
        $this->repo->sendInvitation($meeting);

        return $this->success(['message' => __('global.sent', ['attribute' => __('meeting.invitation')])]);
    }

    /**
     * Toggle meeting moderator
     * @post ("/api/meeting/{meeting}/moderator")
     * @return array
     */
    public function toggleModerator(Meeting $meeting)
    {
        $this->repo->toggleModerator($meeting);

        return $this->success(['message' => __('global.updated', ['attribute' => __('meeting.moderator')])]);
    }

    /**
     * Join meeting
     * @post ("/api/meeting/{meeting}/join")
     * @return array
     */
    public function join(Meeting $meeting)
    {
        $meeting = $this->repo->join($meeting);

        return $this->success(['message' => __('meeting.invitee_joined'), 'meeting' => new MeetingResource($meeting)]);
    }

    /**
     * Leave meeting
     * @post ("/api/meeting/{meeting}/leave")
     * @return array
     */
    public function leave(Meeting $meeting)
    {
        $meeting = $this->repo->leave($meeting);

        return $this->success(['message' => __('meeting.invitee_left'), 'meeting' => new MeetingResource($meeting)]);
    }

    /**
     * End meeting
     * @post ("/api/meeting/{meeting}/end")
     * @return array
     */
    public function end(Meeting $meeting)
    {
        $meeting->isAccessible(true);

        $meeting = $this->repo->end($meeting);

        return $this->success(['message' => __('meeting.invitee_ended'), 'meeting' => new MeetingResource($meeting)]);
    }

    /**
     * Delete meeting invitee
     * @get ("/api/meeting/{meeting}/invitees/{invitee_uuid}")
     * @return array
     */
    public function deleteInvitee(Meeting $meeting, $invitee_uuid)
    {
        $this->repo->deleteInvitee($meeting, $invitee_uuid);

        return $this->success(['message' => __('global.deleted', ['attribute' => __('meeting.invitee.invitee')])]);
    }
}