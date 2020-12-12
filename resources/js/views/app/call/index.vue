<template>
    <div class="entity-list-container">
        <collapse-transition :group="true" :duration="300" tag="div">
            <filter-form v-if="showFilters" @close="toggleFilter" key="filters" :boxed="true" :pre-requisite="preRequisite" :is-loading="isLoading" />
            
            <base-container boxed with-loader :is-loading="isLoading" :loader-color="vars.loaderColor" class="p-0  zoom-print-85" key="list">

                <table-wrapper v-if="isInitialized" :meta="entities.meta" :filtered="isFiltered" add-button-route="appMeetingAdd" :add-button-permissions="['create-meeting']" entity-title="meeting.meeting" entities-title="meeting.meetings" entity-description="meeting.module_description">

                    <b-table v-show="entities.meta.total" ref="btable" :items="itemsProvider" :fields="fields" :busy.sync="isLoading" hover striped stacked="sm" :per-page.number="entities.meta.perPage" :current-page="entities.meta.currentPage" :filters="null" @row-dblclicked="rowClickHandler({route: 'appMeetingView'}, $event)">

                        <template #cell(title)="row">
                            <router-link class="row-link" :to="{ name: 'appMeetingView', params: { uuid: row.item.uuid } }">
                                {{ row.item.title }}
                            </router-link>
                        </template>

                        <template #cell(createdAt)="row">
                            <view-date :value="row.item.createdAt" :to-format="vars.defaultDateTimeFormat" tag="span" class="mb-0" />
                        </template>

                        <template #cell(updatedAt)="row">
                            <view-date :value="row.item.updatedAt" :to-format="vars.defaultDateTimeFormat" tag="span" class="mb-0" />
                        </template>

                        <template #cell(startDateTime)="row">
                            <view-date :value="row.item.startDateTime" :to-format="vars.defaultDateTimeFormat" tag="span" class="mb-0" />
                        </template>

                        <template #cell(period)="row">
                            <view-single :value="row.item.period" tag="span" class="mb-0" />
                        </template>

                        <template #cell(startDatedTime)="row">
                            <div class="d-flex" v-if="sameDate(row.item)">
                                <view-date :value="row.item.startDateTime" :to-format="vars.defaultDateFormat" tag="span" class="mb-0" />

                                <span class="mx-2">-</span>
                                <view-date :value="row.item.startDateTime" :to-format="vars.defaultTimeFormat" tag="span" class="mb-0" />
                                <span class="mx-2">{{ $t('general.to') }}</span>
                                <view-date :value="row.item.endDateTime" :to-format="vars.defaultTimeFormat" tag="span" class="mb-0" />
                            </div>
                            <div class="d-flex" v-else>
                                <view-date :value="row.item.startDateTime" :to-format="vars.defaultDateTimeFormat" tag="span" class="mb-0" />
                                <span class="mx-2">{{ $t('general.to') }}</span>
                                <view-date :value="row.item.endDateTime" :to-format="vars.defaultDateTimeFormat" tag="span" class="mb-0" />
                            </div>
                        </template>

                        <template #cell(type)="row">
                            <badge v-if="row.item.type" type="default" class="mb-0">{{ row.item.type.name }}</badge>
                        </template>

                        <template #cell(category)="row">
                            <badge v-if="row.item.category" type="dark" class="mb-0">{{ row.item.category.name }}</badge>
                        </template>

                        <template #cell(status)="row">
                            <badge v-if="row.item.status" rounded :type="vars.colorsForStatus['meeting-'+row.item.status]">{{ row.item.status }}</badge>
                        </template>

                        <template #cell(actions)="row">
                            <table-row-actions>
                                <router-link class="dropdown-item" :to="{ name: 'appMeetingView', params: { uuid: row.item.uuid } }"><i class="fas fa-arrow-circle-right"></i> {{ $t('global.view', { attribute: $t('meeting.meeting')}) }}</router-link>

                                <router-link v-if="row.item.status === 'scheduled' && (hasPermission('create-meeting') || row.item.canModerate)" class="dropdown-item" :to="{ name: 'appMeetingEdit', params: { uuid: row.item.uuid } }"><i class="fas fa-edit"></i> {{ $t('global.edit', { attribute: $t('meeting.meeting')}) }}</router-link>

                                <router-link v-if="hasPermission('create-meeting')" class="dropdown-item" :to="{ name: 'appMeetingDuplicate', params: { uuid: row.item.uuid } }"><i class="fas fa-copy"></i> {{ $t('global.duplicate', { attribute: $t('meeting.meeting')}) }}</router-link>

                                <router-link v-if="row.item.status === 'scheduled' && (hasPermission('list-meeting') && row.item.canModerate)" class="dropdown-item" :to="{ name: 'appMeetingSingleConfig', params: { subUuid: row.item.uuid } }"><i class="fas fa-cog"></i> {{ $t('global.config', { attribute: $t('meeting.meeting')}) }}</router-link>

                                <a v-if="hasPermission('delete-meeting')" class="dropdown-item" @click.stop="deleteEntity(row.item)"><i class="fas fa-trash"></i> {{ $t('global.delete', { attribute: $t('meeting.meeting')}) }}</a>
                            </table-row-actions>
                        </template>

                    </b-table>
                </table-wrapper>
            </base-container>
        </collapse-transition>
        
    </div>
</template>

<script>
    import table from '@mixins/table'
    import FilterForm from './filter'
    import { getRegion, getCurrencyDescription } from '@js/helpers/transformers'

    export default {
        components: {
            FilterForm,
        },
        extends: table,
        data() {
            return {
                fields: [
                    {
                        key: 'title',
                        label: $t('meeting.props.title'),
                        sort: 'title',
                        transformer: 'limitWords',
                        tdClass: 'td-ellipsis max-width-250px',
                    },
                    {
                        key: 'user.name',
                        label: $t('user.user'),
                    },
                    {
                        key: 'agenda',
                        label: $t('meeting.props.agenda'),
                        transformer: 'limitWords',
                        tdClass: 'd-none td-ellipsis max-width-100px',
                        thClass: 'd-none',
                    },
                    {
                        key: 'type',
                        label: $t('meeting.props.type'),
                        transformer: 'objectWithName'
                    },
                    {
                        key: 'category',
                        label: $t('meeting.meeting_category.category'),
                        transformer: 'objectWithName'
                    },
                    {
                        key: 'status',
                        label: $t('meeting.props.status'),
                    },
                    {
                        key: 'startDateTime',
                        label: $t('meeting.props.scheduled_on'),
                        sort: 'start_date_time',
                        transformer: 'datetime',
                    },
                    {
                        key: 'period',
                        label: $t('meeting.props.estimated_period'),
                        thClass: 'd-none',
                        tdClass: 'd-none',
                    },
                    {
                        key: 'createdAt',
                        label: $t('general.created_at'),
                        sort: 'created_at',
                        transformer: 'datetime',
                        thClass: 'd-none',
                        tdClass: 'd-none',
                    },
                    {
                        key: 'updatedAt',
                        label: $t('general.updated_at'),
                        sort: 'updated_at',
                        transformer: 'datetime',
                        thClass: 'd-none',
                        tdClass: 'd-none',
                    },
                    {
                        key: 'actions',
                        label: '',
                        cantHide: true,
                        tdClass: 'actions-dropdown-wrapper'
                    },
                ],
                filtersOptions: {
                    name: '',
                },
                sortOptions: {
                    hasScroll: true,
                },
                columnsOptions: {
                    hasScroll: true,
                },
                exportOptions: {
                    orientation: 'l',
                },
                permissionsRequired: {
                    add: 'create-meeting',
                    config: 'access-meeting-config',
                },
                routesRequired: {
                    add: 'appMeetingAdd',
                    config: 'appMeetingConfigGeneral',
                },
                initUrl: 'meetings',
                dataType: 'meeting',
            }
        },
        methods: {
            sameDate({startDateTime, endDateTime}) {
                return moment(startDateTime, this.vars.serverDateTimeFormat).format(this.vars.defaultDateFormat) === moment(endDateTime, this.vars.serverDateTimeFormat).format(this.vars.defaultDateFormat)
            }
        },
        mounted() {
            this.updatePageMeta()
        },
    }

</script>
