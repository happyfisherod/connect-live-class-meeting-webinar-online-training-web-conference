<?php

namespace App\Repositories;

use App\Models\Contact;
use App\Http\Resources\ContactCollection;
use App\Repositories\Auth\UserRepository;
use App\Repositories\SegmentRepository;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Validation\ValidationException;

class ContactRepository
{
    protected $contact;
    protected $segment;
    protected $user;

    /**
     * Instantiate a new instance
     * @return void
     */
    public function __construct(
        Contact $contact,
        SegmentRepository $segment,
        UserRepository $user
    ) {
        $this->contact = $contact;
        $this->segment = $segment;
        $this->user = $user;
    }

    /**
     * Get all segments
     */
    public function getAll() : ContactCollection
    {
        return new ContactCollection($this->contact->all());
    }

    /**
     * Find contact with given id or throw an error
     * @param integer $id
     */
    public function findOrFail($id, $field = 'message') : Contact
    {
        $contact = $this->contact->find($id);

        if (! $contact) {
            throw ValidationException::withMessages([$field => __('global.could_not_find', ['attribute' => __('contact.contact')])]);
        }

        return $contact;
    }

    /**
     * Find contact with given uuid or throw an error
     * @param uuid $uuid
     */
    public function findByUuidOrFail($uuid, $field = 'message') : Contact
    {
        $contact = $this->contact->filterByUuid($uuid)->first();

        if (! $contact) {
            throw ValidationException::withMessages([$field => __('global.could_not_find', ['attribute' => __('contact.contact')])]);
        }

        return $contact;
    }

    /**
     * Filter by uuids
     *
     * @param array $uuids
     */
    public function filterByUuids($uuids = array()) : Collection
    {
        return $this->contact->whereIn('uuid', $uuids)->get();
    }

    /**
     * Paginate all contacts
     */
    public function paginate() : ContactCollection
    {
        $sort_by = request()->query('sort_by', 'created_at');
        $order   = request()->query('order', 'desc');
        $name    = request()->query('name');
        $email   = request()->query('email');

        $query = $this->contact->filterByName($name)->filterByEmail($email);

        $per_page     = request('per_page', config('config.system.per_page'));
        $current_page = request('current_page');

        return new ContactCollection($query->orderBy($sort_by, $order)->paginate((int) $per_page, ['*'], 'current_page'));
    }

    /**
     * Get contact pre requisite
     */
    public function getPreRequisite() : array
    {
        $segments = $this->segment->getAll();

        return compact('segments');
    }

    /**
     * Create a new contact
     */
    public function create() : Contact
    {
        \DB::beginTransaction();

        $contact = $this->contact->forceCreate($this->formatParams());

        $user = $this->user->findByEmail($contact->email);

        if ($user) {
            $contact->user_id = $user->id;
            $contact->save();
        }

        $this->syncSegment($contact);

        \DB::commit();

        return $contact;
    }

    /**
     * Prepare given params for inserting into database
     * @param uuid $uuid
     */
    private function formatParams($uuid = null) : array
    {
        $formatted = [
            'name'  => request('name'),
            'email' => request('email'),
        ];

        return $formatted;
    }

    /**
     * Sync contact segment
     *
     * @param Contact $contact
     */
    private function syncSegment(Contact $contact) : void
    {
        $segments = collect(request('segments', []));

        $segments = $this->segment->findIdsByUuids($segments->pluck('uuid')->all());

        $contact->segments()->sync($segments);
    }

    /**
     * Update given contact
     * @param Contact $contact
     */
    public function update(Contact $contact) : Contact
    {
        \DB::beginTransaction();

        $contact->forceFill($this->formatParams($contact->uuid))->save();

        $user = $this->user->findByEmail($contact->email);
        $contact->user_id = $user ? $user->id : null;
        $contact->save();

        $this->syncSegment($contact);

        \DB::commit();

        return $contact;
    }

    /**
     * Delete contact
     * @param Contact $contact
     */
    public function delete(Contact $contact) : void
    {
        $contact->delete();
    }
}
