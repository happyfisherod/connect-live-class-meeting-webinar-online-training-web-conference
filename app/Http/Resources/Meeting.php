<?php

namespace App\Http\Resources;

use App\Helpers\ArrHelper;
use App\Helpers\CalHelper;
use App\Http\Resources\MediaCollection;
use App\Http\Resources\Option;
use App\Http\Resources\User;
use Illuminate\Http\Resources\Json\JsonResource;
use Illuminate\Support\Arr;

class Meeting extends JsonResource
{
    /**
     * Transform the resource into an array.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return array
     */
    public function toArray($request)
    {
        $type = ArrHelper::searchByKey(ArrHelper::getTransList('types', 'meeting'), 'uuid', $this->type);

        $status = $this->getMeta('status');
        $config = $this->getMeta('config');

        return [
           'uuid'                    => $this->uuid,
           'title'                   => $this->title,
           'agenda'                  => $this->agenda,
           'type'                    => $type,
           'category'                => new Option($this->whenLoaded('category')),
           'description'             => $this->description,
           'start_date_time'         => CalHelper::toDateTime($this->start_date_time),
           'period'                  => $this->period,
           'attachments'             => new MediaCollection($this->getMedia()),
           'planned_start_date_time' => CalHelper::toDateTime($this->planned_start_date_time),
           'status'                  => $status,
           'config'                  => array(
               'enable_comments' => Arr::get($config, 'enable_comments') ? true : false,
               'private_comments' => Arr::get($config, 'private_comments') ? true : false,
               'enable_comment_before_meeting_starts' => Arr::get($config, 'enable_comment_before_meeting_starts') ? true : false
           ),
           'delayed'                 => $this->getMeta('snooze_logs') ? true : false,
           'cancellation_reason'     => $this->getMeta('cancellation_reason') ? : null,
           'room_id'                 => $this->when($status === 'live', $this->getMeta('room_id')),
           'started_at'              => CalHelper::toDateTime($this->getMeta('started_at')),
           'ended_at'                => CalHelper::toDateTime($this->getMeta('ended_at')),
           'user'                    => new User($this->whenLoaded('user')),
           'can_moderate'            => $this->when(true, $this->isAccessible(true)),
           'created_at'              => $this->created_at->format(CalHelper::getSysDateTimeFormat()),
           'updated_at'              => $this->updated_at->format(CalHelper::getSysDateTimeFormat())
        ];
    }
}
