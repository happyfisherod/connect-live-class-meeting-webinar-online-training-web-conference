<?php
use App\Helpers\ArrHelper;
use App\Helpers\CalHelper;
use Illuminate\Support\Facades\Broadcast;
use App\Models\Meeting;

/*
|--------------------------------------------------------------------------
| Broadcast Channels
|--------------------------------------------------------------------------
|
| Here you may register all of the event broadcasting channels that your
| application supports. The given channel authorization callbacks are
| used to check if an authenticated user can listen to the channel.
|
*/

// Broadcast::channel('User.{uuid}', function ($user, $uuid) {
//     return $user && $user->uuid === $uuid;
// });

Broadcast::channel('Users', function ($user) {
    $gender = ArrHelper::searchByKey(ArrHelper::getTransList('genders'), 'uuid', $user->gender);

    return [
        'uuid'       => $user->uuid,
        'username'   => $user->username,
        'name'       => $user->name,
        'avatar'     => $user->avatar,
        'gender'     => $gender,
        'birth_date' => CalHelper::toDate($user->birth_date),
        'age'        => CalHelper::getAge($user->birth_date),
        'busy'       => false
    ];
});

Broadcast::channel('Meeting.{uuid}', function ($user, $uuid) {
    $meeting = Meeting::filterByUuid($uuid)->first();

    if (!$meeting) {
        return null;
    }

    return ['uuid' => $user->uuid, 'username' => $user->username, 'name' => $user->name];
});
