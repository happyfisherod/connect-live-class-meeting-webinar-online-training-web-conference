<template>
    <base-container boxed with-loader :is-loading="isLoading" :loader-color="vars.loaderColor" id="printable">
        <form @submit.prevent="submit">
            
            <base-select class="mb-3" :options="preRequisite.segments" v-model="formData.segments" :label="formLabels.segments" :error.sync="formErrors.segments" multiple :close-on-select="false" :allow-empty="true" />

            <base-select class="mb-3" :options="preRequisite.contacts" v-model="formData.contacts" :label="formLabels.contacts" :error.sync="formErrors.contacts" multiple :close-on-select="false" :allow-empty="true" />

            <div class="form-footer mt-5">
                <div class="left-side">
                    <base-button type="button" design="light" @click="$router.back()" tabindex="-1"><i class="fas fa-chevron-left"></i> {{ $t('general.cancel') }}</base-button>
                </div>
                <div class="right-side">
                    <base-button type="button" design="light" @click="reset">{{ $t('general.reset') }}</base-button>
                    <base-button type="submit" design="primary">{{ $t('global.save', { attribute: $t('meeting.invitee.invitees') } ) }}</base-button>
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
                    uuid: null,
                    segments: [],
                    contacts: [],
                },
                preRequisite: {
                    segments: [],
                    contacts: [],
                },
                formLabels: {
                    segments: $t('contact.segment.segments'),
                    contacts: $t('contact.contacts'),
                },
                initUrl: 'meetings',
                initSubUrl: 'invitees',
            }
        },
        mounted() {
            this.getInitialData()
        },
        beforeRouteLeave(to, from, next) {
            EventBus.$emit('ROUTE_LEAVING', next)
        },
    }

</script>
