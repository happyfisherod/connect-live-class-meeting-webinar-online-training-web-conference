<?php

namespace App\Http\Resources;

use App\Helpers\CalHelper;
use Illuminate\Http\Resources\Json\JsonResource;

class Segment extends JsonResource
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
           'meta'       => $this->meta,
           'created_at' => $this->created_at->format(CalHelper::getSysDateTimeFormat()),
           'updated_at' => $this->updated_at->format(CalHelper::getSysDateTimeFormat())
        ];
    }
}
