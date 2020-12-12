<template>
    <div class="row">
        <div class="col-12 col-md-4">
            <base-container boxed with-loader min-height="full" has-footer :is-loading="isLoading" :loader-color="vars.loaderColor" id="printable">

                <template v-if="entity">
                    <div class="row">
                        <div class="col-12 mb-3">
                            <view-single :label="$t('meeting.props.title')" :value="entity.title" tag="h5" data-classes="font-weight-600" />
                        </div>

                        <div class="col-12 mb-3">
                            <view-single :label="$t('meeting.props.type')">
                                <template #main>
                                    <badge v-if="entity.type" type="default" class="mb-0">{{ entity.type.name }}</badge>
                                </template>
                            </view-single>
                        </div>

                        <div class="col-12 mb-3">
                            <view-single :label="$t('meeting.meeting_category.category')">
                                <template #main>
                                    <badge v-if="entity.category" type="dark" class="mb-0">{{ entity.category.name }}</badge>
                                </template>
                            </view-single>
                        </div>

                        <div class="col-12 mb-3">
                            <view-single :label="$t('meeting.props.status')">
                                <template #main>
                                    <badge rounded :type="vars.colorsForStatus['meeting-'+entity.status]">{{ entity.status }}</badge>
                                </template>
                            </view-single>
                        </div>

                        <div v-if="entity && entity.status === 'cancelled'" class="col-12 mb-3">
                            <view-single :label="$t('meeting.props.cancellation_reason')"  :value="entity.cancellationReason"/>
                        </div>

                        <div class="col-12 mb-3">
                            <view-date :label="$t('meeting.props.start_date_time')" :value="entity.startDateTime" :to-format="vars.defaultDateTimeFormat" />
                        </div>

                        <div class="col-12 mb-3">
                            <view-single :label="$t('meeting.props.estimated_period')" :value="entity.period" />
                        </div>

                        <div class="col-12 mb-3">
                            <view-single :label="$t('meeting.config.enable_comments')">
                                <template #main>
                                    <badge v-if="entity.config.enableComments" rounded type="primary"><i class="far fa-check-circle"></i> {{ $t('general.yes') }}</badge>
                                    <badge v-else rounded type="dark"><i class="far fa-circle"></i> {{ $t('general.no') }}</badge>
                                </template>
                            </view-single>
                        </div>

                        <div v-if="entity.config.enableComments" class="col-12 mb-3">
                            <view-single :label="$t('meeting.config.private_comments')">
                                <template #main>
                                    <badge v-if="entity.config.privateComments" rounded type="primary"><i class="far fa-check-circle"></i> {{ $t('general.yes') }}</badge>
                                    <badge v-else rounded type="dark"><i class="far fa-circle"></i> {{ $t('general.no') }}</badge>
                                </template>
                            </view-single>
                        </div>

                        <div class="col-12 mb-3">
                            <view-paragraph class="mb-4" :label="$t('meeting.props.agenda')" :value="entity.agenda" />
                        </div>

                    </div>
                </template>

                <div class="form-footer mt-3">
                    <div class="left-side">
                        <base-button type="button" design="light" @click="$router.back()" tabindex="-1"><i class="fas fa-chevron-left"></i> {{ $t('general.back') }}</base-button>
                    </div>
                    <div class="right-side">
                        <base-button v-if="entity && entity.status === 'scheduled' && (hasPermission('edit-meeting') || entity.canModerate)" type="button" design="primary" @click.stop="$router.push({ name: 'appMeetingEdit', params: { uuid: entity.uuid } })"><i class="fas fa-edit"></i> {{ $t('global.edit', { attribute: $t('meeting.meeting') } ) }}</base-button>
                    </div>
                </div>
            </base-container>
        </div>

        <template v-if="entity">

            <div v-if="entity.canModerate" class="col-12 col-md-8">

                <base-container boxed with-loader min-height="full" :is-loading="isLoading" :loader-color="vars.loaderColor" class="p-0">

                    <table-wrapper v-if="isInitialized" :meta="entities.meta" :add-button-route="entity.status === 'scheduled' && entity.canModerate ? 'appMeetingInviteeAdd' : ''" :add-button-params="{ 'subUuid': uuid }" :add-button-permissions="['create-meeting']" entity-title="meeting.invitee.invitee" entities-title="meeting.invitee.invitees" entity-description="meeting.invitee.module_description" small-footer>

                        <b-table v-show="entities.meta.total" ref="btable" :items="itemsProvider" :fields="fields" :busy.sync="isLoading" hover striped stacked="sm" :per-page.number="entities.meta.perPage" :current-page="entities.meta.currentPage" :filters="null">

                            <template #cell(isModerator)="row">
                                <span v-if="row.item.isModerator" class="text-success"><i class="fas fa-check-circle"></i></span>
                                <span v-else class="text-light"><i class="far fa-circle"></i></span>
                            </template>

                            <template #cell(isAttendee)="row">
                                <span v-if="row.item.isAttendee" class="text-success"><i class="fas fa-check-circle"></i></span>
                                <span v-else class="text-light"><i class="far fa-circle"></i></span>
                            </template>

                            <template #cell(actions)="row">
                                <div class="btn-group" role="group" aria-label="Actions Buttons" v-if="entity.status === 'scheduled'">
                                    <base-button v-if="hasPermission('create-meeting')" type="button" size="sm" design="dark" v-b-tooltip.hover.d500 :title="$t('global.toggle', { attribute: $t('meeting.moderator')})" @click.stop="toggleModerator(row.item)">
                                        <i v-if="row.item.isModerator" class="fas fa-times-circle"></i>
                                        <i v-else class="fas fa-check-circle"></i>
                                    </base-button>

                                    <base-button v-if="hasPermission('create-meeting')" type="button" size="sm" design="dark" v-b-tooltip.hover.d500 :title="$t('global.delete', { attribute: $t('meeting.invitee.invitee')})" @click.stop="deleteEntity(row.item)"><i class="fas fa-trash"></i></base-button>

                                    <base-button v-if="entity.canModerate" type="button" size="sm" design="dark" v-b-tooltip.hover.d500 :title="$t('meeting.send_invitation')" @click.stop="sendInvitation(row.item)"><i class="fas fa-paper-plane"></i></base-button>
                                </div>
                            </template>

                        </b-table>
                    </table-wrapper>

                </base-container>
            </div>

            <div :class="['col-12', {'col-md-8': !entity.canModerate}, {'mt-element': entity.canModerate}]">
                <base-container boxed>
                    <view-paragraph :label="$t('meeting.props.description')" :value="entity.description" html />
                </base-container>
            </div>

            <div class="col-12 mt-element" v-if="entity && entity.status === 'scheduled' && (hasPermission('edit-meeting') || entity.canModerate)">
                <base-container boxed>
                    <file-uploader :url="`/${this.initUrl}/${this.uuid}/media`" name-label="upload.attachment" names-label="upload.attachments" :options="uploaderConfig" :data="entity.attachments" button-wrapper-classes="justify-content-between" heading-classes="text-muted mb-0" :heading="$t('upload.attachments')" />
                </base-container>
            </div>

            <div class="col-12 mt-element" v-else-if="entity && entity.attachments && entity.attachments.length">
                <base-container boxed>
                    <view-uploads class="mt-3" :label="$t('upload.attachments')" :name-label="$t('upload.attachment')" :value="entity.attachments" :url-prefix="`/meetings/${uuid}/downloads`" />
                </base-container>
            </div>
        </template>
    </div>
</template>

<script>
    import table from '@mixins/table'
    import * as headerMixins from '@mixins/header'
    import Swal from '@core/configs/sweet-alert'
    import FileUploader from '@components/FileUploader'

    export default {
        extends: table,
        components: {
            FileUploader,
        },
        data() {
            return {
                fields: [{
                        key: 'contact.email',
                        label: $t('contact.props.email'),
                    },
                    {
                        key: 'contact.name',
                        label: $t('contact.props.name'),
                    },
                    {
                        key: 'isModerator',
                        label: $t('meeting.is_moderator'),
                        tdClass: 'd-none',
                        thClass: 'd-none',
                    },
                    {
                        key: 'isAttendee',
                        label: $t('meeting.is_attendee'),
                        tdClass: 'd-none',
                        thClass: 'd-none',
                    },
                    {
                        key: 'actions',
                        label: '',
                        cantHide: true,
                        tdClass: 'actions-wrapper'
                    },
                ],
                initUrl: 'meetings',
                initSubUrl: 'invitees',
                dataTitle: $t('meeting.meeting'),
                fallBackRoute: 'appMeetingList',
                dataType: 'meeting',
                hideFilterButton: true,
                uploaderConfig: { 
                    module: '',
                    token: '',
                    allowedExtensions: '',
                    maxNoOfFiles: 5,
                    uuid: uuid(),
                },
            }
        },
        methods: {
            afterGetEntityData() {
                this.headerButtons = []

                if(this.entity.status === 'scheduled' || this.entity.status === 'live') {

                    this.headerButtons.push(headerMixins.headerPermittedRouteButton($t('meeting.join'), 'fas fa-sign-in-alt', 'liveMeeting', 'list-meeting', null, { color: 'success' }, { subUuid: this.uuid }))
                }

                if(this.entity.status === 'scheduled' && this.entity.canModerate) {

                    this.headerButtons.push(headerMixins.headerActionButton($t('meeting.cancel'), 'fas fa-times', this.cancelMeeting, null, { color: 'danger' }))

                    this.headerButtons.push(headerMixins.headerActionButton($t('meeting.invite'), 'fas fa-paper-plane', this.triggerSendInvitation, null, { color: 'primary' }))

                    this.headerButtons.push(headerMixins.headerRouteButton($t('general.add'), 'fas fa-plus', 'appMeetingInviteeAdd', null, null, { subUuid: this.uuid }))

                    this.headerButtons.push(headerMixins.headerRouteButton(null, 'fas fa-cog', 'appMeetingSingleConfig', null, null, { subUuid: this.uuid }))
                }

                this.applyPageHeader()
            },
            cancelMeeting() {
                swtAlert.fire({
                        title: $t('meeting.reason_for_cancellation'),
                        input: 'text',
                        inputPlaceholder: $t('meeting.reason_for_cancellation'),
                        showCancelButton: true,
                        confirmButtonText: 'Proceed!',
                        cancelButtonText: 'Go Back!'
                    })
                    .then((result) => {
                        if (result.value) {
                            this.isLoading = true

                            this.Custom({
                                    url: `/${this.initUrl}/${this.uuid}/cancel`,
                                    method: 'post',
                                    data: {
                                        cancellationReason: result.value
                                    }
                                })
                                .then(response => {
                                    this.entity = response.meeting
                                    this.afterGetEntityData()
                                    this.$toasted.success(response.message, this.$toastConfig)
                                    this.isLoading = false
                                })
                                .catch(error => {
                                    this.isLoading = false
                                    formUtil.handleErrors(error)
                                })
                        } else {
                            result.dismiss === Swal.DismissReason.cancel
                        }
                    })
            },
            sendInvitation(invitee) {
                formUtil.confirmAction()
                    .then((result) => {
                        if (result.value) {
                            this.isLoading = true
                            let data = {}

                            if (invitee) {
                                data.invitee = invitee
                            }

                            this.Custom({
                                    url: `/${this.initUrl}/${this.uuid}/invitation`,
                                    method: 'post',
                                    data
                                })
                                .then(response => {
                                    this.$toasted.success(response.message, this.$toastConfig.success)
                                    this.isLoading = false
                                })
                                .catch(error => {
                                    this.isLoading = false
                                    formUtil.handleErrors(error)
                                })
                        } else {
                            result.dismiss === Swal.DismissReason.cancel
                        }
                    })
            },
            triggerSendInvitation() {
                this.sendInvitation()
            },
            toggleModerator(invitee) {
                this.isLoading = true
                let data = {}

                if (invitee) {
                    data.invitee = invitee
                }
                this.Custom({
                        url: `/${this.initUrl}/${this.uuid}/moderator`,
                        method: 'post',
                        data
                    })
                    .then(response => {
                        this.isLoading = false
                        this.$nextTick(() => {
                            this.refreshTable()
                        });
                    })
                    .catch(error => {
                        this.isLoading = false
                        formUtil.handleErrors(error)
                    })
            },
        },
        mounted() {
            this.getEntityData()
        },
    }

</script>
