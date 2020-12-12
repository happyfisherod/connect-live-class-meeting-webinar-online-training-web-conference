<?php

namespace App\Http\Resources;

use App\Helpers\CalHelper;
use App\Http\Resources\Contact;
use Illuminate\Http\Resources\Json\JsonResource;

class Invitee extends JsonResource
{
    /**
     * Transform the resource into an array.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return array
     */
    public function toArray($request)
    {
        return [
           'uuid'         => $this->uuid,
           'contact'      => new Contact($this->whenLoaded('contact')),
           'is_attendee'  => $this->is_attendee ? true : false,
           'is_moderator' => $this->getMeta('is_moderator') ? true : false,
           'created_at'   => $this->created_at->format(CalHelper::getSysDateTimeFormat()),
           'updated_at'   => $this->updated_at->format(CalHelper::getSysDateTimeFormat())
        ];
    }
}
