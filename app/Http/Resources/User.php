<?php

namespace App\Http\Resources;

use App\Helpers\ArrHelper;
use App\Helpers\CalHelper;
use App\Http\Resources\Config\RoleCollection;
use Illuminate\Http\Resources\Json\JsonResource;

class User extends JsonResource
{
    /**
     * Transform the resource into an array.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return array
     */
    public function toArray($request)
    {
        $gender = ArrHelper::searchByKey(ArrHelper::getTransList('genders'), 'uuid', $this->gender);

        return [
           'uuid'         => $this->uuid,
           'username'     => $this->username,
           'email'        => $this->email,
           'enable_login' => $this->status != 'activated' ? false : true,
           'status'       => $this->status,
           'profile'     => array(
               'name'       => $this->name,
               'avatar'     => $this->avatar,
               'gender'     => $gender,
               'birth_date' => CalHelper::toDate($this->birth_date),
               'age'        => CalHelper::getAge($this->birth_date)
           ),
           'roles'        => new RoleCollection($this->whenLoaded('roles')),
           'created_at'   => CalHelper::toDateTime($this->created_at),
           'updated_at'   => CalHelper::toDateTime($this->updated_at)
        ];
    }
}