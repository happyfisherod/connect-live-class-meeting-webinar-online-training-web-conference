<template>
    <base-container boxed with-loader :is-loading="isLoading" :loader-color="vars.loaderColor" id="printable">
        <form @submit.prevent="submit">
            
            <div class="row">
                <div class="col-12 col-md-4 mb-3">
                    <switch-wrapper class="mt-4 mb-3" :label="formLabels.enableComments">
                        <base-switch v-model="formData.enableComments"></base-switch>
                    </switch-wrapper>
                </div>
                <template v-if="formData.enableComments">
                    <div class="col-12 col-md-4 mb-3">
                        <switch-wrapper class="mt-4 mb-3" :label="formLabels.privateComments">
                            <base-switch v-model="formData.privateComments"></base-switch>
                        </switch-wrapper>
                    </div>
                    <div class="col-12 col-md-4 mb-3">
                        <switch-wrapper class="mt-4 mb-3" :label="formLabels.enableCommentBeforeMeetingStarts">
                            <base-switch v-model="formData.enableCommentBeforeMeetingStarts"></base-switch>
                        </switch-wrapper>
                    </div>
                </template>
            </div>

            <div class="form-footer mt-5">
                <div class="left-side">
                    <base-button type="button" design="light" @click="$router.back()" tabindex="-1"><i class="fas fa-chevron-left"></i> {{ $t('general.cancel') }}</base-button>
                </div>
                <div class="right-side">
                    <base-button type="button" design="light" @click="reset">{{ $t('general.reset') }}</base-button>
                    <base-button type="submit" design="primary">{{ $t('global.save', { attribute: $t('config.config') } ) }}</base-button>
                </div>
            </div>
        </form>
    </base-container>
</template>

<script>
    import form from '@mixins/form'
    import EventBus from '@js/event-bus'

    export default {
        extends: form,
        data() {
            return {
                formData: {
                    enableComments: false,
                    privateComments: false,
                    enableCommentBeforeMeetingStarts: true,
                },
                formLabels: {
                    enableComments: $t('meeting.config.enable_comments'),
                    privateComments: $t('meeting.config.private_comments'),
                    enableCommentBeforeMeetingStarts: $t('meeting.config.enable_comment_before_meeting_starts'),
                },
                initUrl: 'meetings',
                initSubUrl: 'config',
            }
        },
        methods: {
            getMeeting() {  
                this.isLoading = true
                this.doInit()
                this.Get(this.subUuid)
                    .then(response => {
                        this.doInitSub()
                        if(response.config) {
                            this.formData.objForEach((value, key) => {
                                this.formData[key] = response.config[key] || this.formData[key]
                            })
                        }
                        this.initialFormData = _.cloneDeep(this.formData)
                        this.isLoading = false
                    })
                    .catch(error => {
                        this.isLoading = false
                        formUtil.handleErrors(error)
                    }) 
            }
        },
        mounted() {
            this.getMeeting()
        },
        beforeRouteLeave(to, from, next) {
            EventBus.$emit('ROUTE_LEAVING', next)
        },
    }

</script>
