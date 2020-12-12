<?php

namespace App\Models\Config;

use Illuminate\Support\Arr;
use Illuminate\Database\Eloquent\Model;

class Config extends Model
{
    protected $fillable = ['name', 'value'];

    const ASSET_TYPES = [
        'logo',
        'logo_light',
        'icon',
        'favicon'
    ];

    protected $casts = [
        'value' => 'json',
        'meta'  => 'json'
    ];

    public function getValue(string $option)
    {
        return Arr::get($this->value, $option);
    }
}
