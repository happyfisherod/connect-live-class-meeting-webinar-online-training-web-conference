<?php

namespace App\Repositories;

use App\Models\Segment;
use App\Http\Resources\SegmentCollection;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Validation\ValidationException;

class SegmentRepository
{
    protected $segment;

    /**
     * Instantiate a new instance
     * @return void
     */
    public function __construct(
        Segment $segment
    ) {
        $this->segment = $segment;
    }

    /**
     * Get all segments
     */
    public function getAll() : SegmentCollection
    {
        return new SegmentCollection($this->segment->all());
    }

    /**
     * Find segment with given id or throw an error
     * @param integer $id
     */
    public function findOrFail($id, $field = 'message') : Segment
    {
        $segment = $this->segment->find($id);

        if (! $segment) {
            throw ValidationException::withMessages([$field => __('global.could_not_find', ['attribute' => __('contact.segment.segment')])]);
        }

        return $segment;
    }

    /**
     * Find segment with given uuid or throw an error
     * @param uuid $uuid
     */
    public function findByUuidOrFail($uuid, $field = 'message') : Segment
    {
        $segment = $this->segment->filterByUuid($uuid)->first();

        if (! $segment) {
            throw ValidationException::withMessages([$field => __('global.could_not_find', ['attribute' => __('contact.segment.segment')])]);
        }

        return $segment;
    }

    /**
     * Find segment with given uuid or throw an error
     * 
     * @param array $uuids
     */
    public function findIdsByUuids($uuids) : array
    {
        return $this->segment->whereIn('uuid', $uuids)->get()->pluck('id')->all();
    }

    /**
     * Filter by uuids
     *
     * @param array $uuids
     */
    public function filterByUuids($uuids = array()) : Collection
    {
        return $this->segment->with('contacts')->whereIn('uuid', $uuids)->get();
    }

    /**
     * Paginate all segments
     */
    public function paginate() : SegmentCollection
    {
        $sort_by    = request()->query('sort_by', 'created_at');
        $order      = request()->query('order', 'desc');
        $name       = request()->query('name');

        $query = $this->segment->filterByName($name);

        $per_page     = request('per_page', config('config.system.per_page'));
        $current_page = request('current_page');

        return new SegmentCollection($query->orderBy($sort_by, $order)->paginate((int) $per_page, ['*'], 'current_page'));
    }

    /**
     * Create a new segment
     */
    public function create() : Segment
    {
        return $this->segment->forceCreate($this->formatParams());
    }

    /**
     * Prepare given params for inserting into database
     * @param uuid $uuid
     */
    private function formatParams($uuid = null) : array
    {
        $formatted = [
            'name'        => request('name'),
            'description' => request('description'),
        ];

        return $formatted;
    }

    /**
     * Update given segment
     * @param Segment $segment
     */
    public function update(Segment $segment) : Segment
    {
        $segment->forceFill($this->formatParams($segment->uuid))->save();

        return $segment;
    }

    /**
     * Delete segment
     * @param Segment $segment
     */
    public function delete(Segment $segment) : void
    {
        $segment->delete();
    }
}
