<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

class MeetingRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     *
     * @return bool
     */
    public function authorize()
    {
        return true;
    }

    /**
     * Get the validation rules that apply to the request.
     *
     * @return array
     */
    public function rules()
    {
        $uuid = $this->route('meeting');

        return [
            'title'           => 'required|min:5',
            'agenda'          => 'required|min:20',
            'start_date_time' => 'required|date',
            'period'          => 'integer|min:1',
            'category'        => 'required|array|min:1',
            'type'            => 'required|array'
        ];
    }
}
