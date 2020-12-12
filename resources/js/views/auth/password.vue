<template>
    <div class="guest-page">
        <box>
            <animated-loader :is-loading="isLoading" :loader-color="vars.loaderColor" />

            <guest-header>
                <h5>{{ $t('auth.password.forgot.page_title') }}</h5>
            </guest-header>

            <section role="main">

                <form @submit.prevent="submit">
                    <base-input :auto-focus="!requested && !validated" :disabled="requested || validated" class="mb-3" :label="$t('auth.password.props.email')" type="text" v-model="formData.email" addon-left-icon="fas fa-envelope" :error.sync="formErrors.email" />

                    <template v-if="requested">
                        <base-input v-if="!validated" :auto-focus="requested && !validated" :disabled="requested && validated" class="mb-3" :label="$t('auth.password.props.code')" type="password" v-model="formData.code" addon-left-icon="fas fa-qrcode" :error.sync="formErrors.code" />

                        <template v-else>
                            <base-input :auto-focus="requested && validated" class="mb-3" :label="$t('auth.password.props.new_password')" type="password" v-model="formData.newPassword" addon-left-icon="fas fa-key" :error.sync="formErrors.newPassword" />

                            <base-input class="mb-3" :label="$t('auth.password.props.new_password_confirmation')" type="password" v-model="formData.newPasswordConfirmation" addon-left-icon="fas fa-key" :error.sync="formErrors.newPasswordConfirmation" />
                        </template>
                    </template>


                    <div class="text-center">
                        <base-button v-if="requested && validated" type="submit" design="primary" block class="my-4 text-lg">{{ $t('auth.password.reset_password') }}</base-button>
                        <base-button v-else-if="requested" type="submit" design="primary" block class="my-4 text-lg">{{ $t('auth.password.validate_code') }}</base-button>
                        <base-button v-else type="submit" design="primary" block class="my-4 text-lg">{{ $t('auth.password.request') }}</base-button>
                    </div>

                    <div class="form-group m-b-0">
                        <div class="col-sm-12 text-center">
                            <p><i class="fas fa-chevron-left"></i>
                                <router-link :to="{ name: 'login' }" class="text-primary m-l-5"><span class="font-weight-bold">{{ $t('auth.login.back_to_login') }}</span></router-link>
                            </p>
                        </div>
                    </div>

                </form>

            </section>

        </box>

        <guest-footer v-if="configs.system" :footer-credit="configs.system.footerCredit" :version="configs.system.version" />

    </div>
</template>

<script>
    import Box from './partials/box'
    import GuestHeader from '@views/layouts/partials/guest-header'
    import GuestFooter from '@views/layouts/partials/guest-footer'
    import { assignErrors } from '@core/utils/form'
    import { mapGetters, mapActions } from 'vuex'
    export default {
        components: {
            Box,
            GuestHeader,
            GuestFooter,
        },
        data() {
            return {
                formData: {
                    email: '',
                    code: '',
                    newPassword: '',
                    newPasswordConfirmation: '',
                },
                formErrors: {},
                isLoading: false,
                requested: false,
                validated: false
            }
        },
        computed: {
            ...mapGetters('config', [
                'configs',
                'vars',
            ]),
        },
        methods: {
            ...mapActions('user', [
                'RequestReset',
                'ValidateResetPassword',
                'ResetPassword',
            ]),
            submit() {
                this.isLoading = true

                if(this.requested && this.validated) {
                    this.ResetPassword(this.formData)
                        .then(response => {
                            this.$toasted.success(response.message, this.$toastConfig)
                            this.$router.push({ name: 'login' })
                        })
                        .catch(error => {
                            this.isLoading = false
                            this.formErrors = formUtil.handleErrors(error)
                        })
                } else if(this.requested) {
                    this.ValidateResetPassword(this.formData)
                        .then(response => {
                            this.$toasted.success(response.message, this.$toastConfig)
                            this.validated = true
                            this.isLoading = false
                        })
                        .catch(error => {
                            this.isLoading = false
                            this.formErrors = formUtil.handleErrors(error)
                        })
                } else {
                    this.RequestReset(this.formData)
                        .then(response => {
                            this.$toasted.success(response.message, this.$toastConfig)
                            this.requested = true
                            this.isLoading = false
                        })
                        .catch(error => {
                            this.isLoading = false
                            this.formErrors = formUtil.handleErrors(error)
                        })
                }
            },
        },
    }

</script>
<style lang="scss" scoped>


</style>
