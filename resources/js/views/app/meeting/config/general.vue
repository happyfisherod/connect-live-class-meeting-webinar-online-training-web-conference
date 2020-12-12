<template>
    <base-container boxed with-loader :is-loading="isLoading" :loader-color="vars.loaderColor">
        <form @submit.prevent="submit">
            <div class="row">
                <div class="col-12 col-md-6">
                    <base-input auto-focus class="mb-5" :label="$t('meeting.config.code_prefix')" type="text" v-model="formData.codePrefix" :error.sync="formErrors.codePrefix" />
                </div>
                <div class="col-12 col-md-6">
                    <base-input class="mb-5" :label="$t('meeting.config.code_digit')" type="number" v-model="formData.codeDigit" :error.sync="formErrors.codeDigit" min="0" />
                </div>
            </div>

            <h5>{{ $t('general.template_placeholders') }}</h5>
            <p class="text-muted small comma-list">
                <span v-for="str in getTemplateStrings()">{{ str.code }} ({{ str.example }})</span>
            </p>

            <div class="form-footer mt-5">
                <div class="left-side">
                    <base-button type="button" design="light" @click="$router.back()" tabindex="-1"><i class="fas fa-chevron-left"></i> {{ $t('general.cancel') }}</base-button>
                </div>
                <div class="right-side">
                    <base-button type="button" design="light" @click="reset">{{ $t('general.reset') }}</base-button>
                    <base-button type="submit" design="primary"><i class="fas fa-save"></i> {{ $t('general.save') }}</base-button>
                </div>
            </div>
        </form>
    </base-container>
</template>

<script>
    import form from '@mixins/config-form'
    import { templateStrings } from '@core/utils/templater'

    export default {
        extends: form,
        data() {
            return {
                formData: {
                    codePrefix: '',
                    codeDigit: 3,
                    type: 'meeting'
                },
            }
        },
        mounted() {
            this.getInitialData()
        },
        methods: {
            getTemplateStrings() {
                let strs = []
                templateStrings.objForEach((value, key) => {
                    strs.push(value)
                })
                return strs
            }
        },
    }

</script>
