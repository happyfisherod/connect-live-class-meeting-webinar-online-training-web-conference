<?php

namespace App\Http\Resources;

use App\Helpers\CalHelper;
use App\Http\Resources\MediaCollection;
use App\Http\Resources\User;
use Illuminate\Http\Resources\Json\JsonResource;

class Comment extends JsonResource
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
           'uuid'        => $this->uuid,
           'body'        => $this->body,
           'attachments' => new MediaCollection($this->getMedia()),
           'meta'        => $this->meta,
           'user'        => new User($this->whenLoaded('user')),
           'created_at'  => $this->created_at->format(CalHelper::getSysDateTimeFormat()),
           'updated_at'  => $this->updated_at->format(CalHelper::getSysDateTimeFormat())
        ];
    }
}
