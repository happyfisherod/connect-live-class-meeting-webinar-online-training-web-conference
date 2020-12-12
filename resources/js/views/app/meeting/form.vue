<template>
    <form @submit.prevent="submit">
        <animated-loader :is-loading="isLoading || isFetching" :loader-color="vars.loaderColor" />

        <div class="row">
            <div class="col-12 col-md-4 mb-3">
                <base-input auto-focus :label="formLabels.title" type="text" v-model="formData.title" :error.sync="formErrors.title" required />
            </div>

            <div class="col-12 col-md-4 mb-3">
                <base-select :options="preRequisite.types" v-model="formData.type" :label="formLabels.type" :error.sync="formErrors.type" required :allow-empty="false" preselect-first />
            </div>

            <div class="col-12 col-md-4 mb-3">
                <base-select :options="preRequisite.categories" v-model="formData.category" :label="formLabels.category" :error.sync="formErrors.category" required :allow-empty="false" preselect-first :add-new-modal="true" needed-permission="access-meeting-config">
                    <template #addNewModal>
                        <option-form :meta="{optionType: 'meeting_category', dataType: 'category', dataTypeArr: 'categories', entityTitle: 'meeting.meeting_category.category'}" @close="newModalClose" />
                    </template>
                </base-select>
            </div>

            <div class="col-12 col-md-4 mb-3">
                <base-input class="mb-3" :label="formLabels.startDateTime" addon-right-icon="far fa-calendar-alt" type="text" v-model="formData.startDateTime" :error.sync="formErrors.startDateTime" :is-wrapper="true" required>
                    <date-picker v-model="formData.startDateTime" :config="vars.datetimepickerConfig" class="form-control datepicker">
                    </date-picker>
                </base-input>


                <base-input class="mb-3" :label="formLabels.period" type="number" v-model="formData.period" :error.sync="formErrors.period" required select-on-focus @wheel.stop.prevent :addon-right-text="$t('list.general.durations.minutes')" />
            </div>

            <div class="col-12 col-md-8 mb-3">
                <base-textarea rows="5" :label="formLabels.agenda" v-model="formData.agenda" :error.sync="formErrors.agenda" required />
            </div>

            <div class="col-12 mt-4 mb-3">
                <editor-wrapper :label="formLabels.description" v-model="formData.description" :error.sync="formErrors.description" />
            </div>
        </div>

        <div class="form-footer mt-5">
            <div class="left-side">
                <base-button type="button" design="light" @click="$router.back()" tabindex="-1"><i class="fas fa-chevron-left"></i> {{ $t('general.cancel') }}</base-button>

                <base-checkbox class="ml-3 mt-2" v-model="keepAdding" v-if="showKeepAdding">
                    {{ $t('general.keep_adding') }}
                </base-checkbox>
            </div>
            <div class="right-side">
                <base-button type="button" design="light" @click="reset">{{ $t('general.reset') }}</base-button>
                <base-button type="submit" design="primary">{{ $t('global.save', { attribute: $t('meeting.meeting') } ) }}</base-button>
            </div>
        </div>

        <template v-if="showKeepAdding && keepAdding">
            <keep-adding-form :keep-adding-fields="keepAddingFields" :keep-adding-option="keepAddingOption" @optionUpdated="keepAddingOption=$event" :keep-adding-selected-fields="keepAddingSelectedFields" @fieldsUpdated="keepAddingSelectedFields=$event" :is-loading="isLoading" />
        </template>
    </form>
</template>

<script>
    import form from '@mixins/form'
    import EditorWrapper from '@core/components/EditorWrapper'
    import OptionForm from '@views/app/option/modal-form'
    import store from '@js/store'
    const vars = store.getters['config/vars']

    export default {
        extends: form,
        components: {
            EditorWrapper,
            OptionForm,
        },
        data() {
            return {
                formData: {
                    uuid: null,
                    title: '',
                    agenda: '',
                    description: '',
                    startDateTime: moment().format(vars.serverDateTimeFormat),
                    period: 60,
                    type: null,
                    category: null,
                },
                preRequisite: {
                    types: [],
                    contacts: [],
                    segments: [],
                    categories: [],
                },
                formLabels: {
                    title: $t('meeting.props.title'),
                    agenda: $t('meeting.props.agenda'),
                    description: $t('meeting.props.description'),
                    startDateTime: $t('meeting.props.start_date_time'),
                    period: $t('meeting.props.estimated_period'),
                    type: $t('meeting.props.type'),
                    category: $t('meeting.meeting_category.category'),
                },
                initUrl: 'meetings',
            }
        },
        methods: {
            afterEditData() {
                if(this.duplicate) {
                    this.formData.startDateTime = moment().format(vars.serverDateTimeFormat)
                }
            },
        },
        mounted() {
            this.getInitialData()
        }
    }

</script>
