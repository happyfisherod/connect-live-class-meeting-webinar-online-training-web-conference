<template>
    <div class="guest-page">
        <box width="xxl">
            <animated-loader :is-loading="isLoading" :loader-color="vars.loaderColor" />

            <template v-if="!registrationPending">
                <guest-header>
                    <h5>{{ $t('auth.register.page_title') }}</h5>
                </guest-header>

                <section role="main">

                    <form @submit.prevent="submit">
                        <base-input auto-focus class="mb-3" :label="$t('auth.register.props.name')" type="text" name="name" v-model="formData.name" addon-left-icon="far fa-id-badge" :error.sync="formErrors.name"></base-input>


                        <div class="row">
                            <div class="col-md-6">
                                <base-input class="mb-3" :label="$t('auth.register.props.email')" type="text" name="email" v-model="formData.email" addon-left-icon="fas fa-envelope" :error.sync="formErrors.email"></base-input>
                            </div>
                            <div class="col-md-6">
                                <base-input class="mb-3" :label="$t('auth.register.props.username')" type="text" name="username" v-model="formData.username" addon-left-icon="fas fa-user" :error.sync="formErrors.username"></base-input>
                            </div>
                            <div class="col-md-6">
                                <base-input class="mb-3" :label="$t('auth.register.props.password')" type="password" name="password" v-model="formData.password" addon-left-icon="fas fa-key" :error.sync="formErrors.password"></base-input>
                            </div>
                            <div class="col-md-6">
                                <base-input class="mb-3" :label="$t('auth.register.props.confirm_password')" type="password" name="passwordConfirmation" v-model="formData.passwordConfirmation" addon-left-icon="fas fa-key" :error.sync="formErrors.passwordConfirmation"></base-input>
                            </div>
                        </div>

                        <div class="text-center mt-4">
                            <base-button type="submit" design="primary" block class="my-4 text-lg">{{ $t('auth.register.register') }}</base-button>
                        </div>

                        <template v-if="configs && configs.auth">

                            <div class="row mt-4">
                                <div class="col-md-12 text-center">
                                    <router-link :to="{ name: 'login' }" class="text-primary m-l-5"> <span class="font-weight-bold">{{ $t('auth.register.already_have_account') }}</span> </router-link>
                                </div>
                            </div>

                        </template>

                    </form>

                </section>
            </template>

            <template v-else>
                <guest-header>
                    <h4 class="text-primary">{{ $t('auth.register.completed') }}</h4>
                </guest-header>

                <div class="text-muted">
                    <h6 class="text-muted text-center">{{ registrationPendingMessage }}</h6>
                </div>

                <div class="row mt-4">
                    <div class="col-md-12 text-center">
                        <router-link :to="{ name: 'login' }" class="text-primary m-l-5"> <span class="font-weight-bold">{{ $t('auth.login.page_title') }}</span> </router-link>
                    </div>
                </div>
            </template>

        </box>

        <guest-footer v-if="configs.system" :footer-credit="configs.system.footerCredit" :version="configs.system.version" />

    </div>
</template>

<script>
    import Box from './partials/box'
    import GuestHeader from '@views/layouts/partials/guest-header'
    import GuestFooter from '@views/layouts/partials/guest-footer'
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
                    name: '',
                    email: '',
                    username: '',
                    password: '',
                    passwordConfirmation: '',
                },
                formErrors: {},
                isLoading: false,
                registrationPending: false,
                registrationPendingMessage: $t('auth.register.pending_verification_message')
            }
        },
        computed: {
            ...mapGetters('config', [
                'configs',
                'vars'
            ]),
        },
        methods: {
            ...mapActions('user', [
                'Register',
            ]),
            submit() {
                this.isLoading = true
                let routeQuery = this.$route.query

                this.Register(this.formData)
                    .then(response => {
                        this.$toasted.success(response.message, this.$toastConfig)

                        if (response.registrationStatus === 'activated') {
                            this.$router.push({ name: 'login' });
                        } else {
                            this.registrationPending = true
                            this.registrationPendingMessage = response.message
                        }
                        this.isLoading = false
                    })
                    .catch(error => {
                        this.isLoading = false
                        this.formErrors = formUtil.handleErrors(error)
                    })
            },
        },
        created() {
            if (this.$route.query.hasOwnProperty('registered')) {
                this.registrationPending = this.$route.query.hasOwnProperty('registered') ? true : false
            }
        }
    }

</script>
<style lang="scss" scoped>


</style>
