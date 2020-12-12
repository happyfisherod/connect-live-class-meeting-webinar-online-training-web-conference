<?php

namespace App\Http\Resources;

use App\Helpers\CalHelper;
use App\Http\Resources\User;
use App\Http\Resources\SegmentCollection;
use Illuminate\Http\Resources\Json\JsonResource;

class Contact extends JsonResource
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
           'uuid'       => $this->uuid,
           'name'       => $this->name,
           'email'      => $this->email,
           'meta'       => $this->meta,
           'segments'   => new SegmentCollection($this->whenLoaded('segments')),
           'user'       => new User($this->whenLoaded('user')),
           'created_at' => $this->created_at->format(CalHelper::getSysDateTimeFormat()),
           'updated_at' => $this->updated_at->format(CalHelper::getSysDateTimeFormat())
        ];
    }
}
