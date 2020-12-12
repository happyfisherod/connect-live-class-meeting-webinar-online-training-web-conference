<template>
    <div class="guest-page">
        <box>
            <animated-loader :is-loading="isLoading" :loader-color="vars.loaderColor" />

            <guest-header>
                <h5>{{ $t('auth.login.page_title') }}</h5>
            </guest-header>

            <section role="main">

                <form @submit.prevent="submit">
                    <base-input auto-focus class="mb-3" :label="$t('auth.login.props.email_username')" type="text" v-model="formData.email" addon-left-icon="fas fa-envelope" :error.sync="formErrors.email">
                    </base-input>

                    <base-input class="mb-3" :label="$t('auth.login.props.password')" type="password" v-model="formData.password" addon-left-icon="fas fa-key" :error.sync="formErrors.password">
                    </base-input>

                    <div class="text-center mt-4">
                        <base-button type="submit" design="primary" block class="my-4 text-lg">{{ $t('auth.login.login') }}</base-button>
                    </div>


                    <template v-if="configs && configs.auth">

                        <template v-if="configs.auth.mobileOtpLogin || configs.auth.emailOtpLogin || configs.auth.socialLogin || configs.auth.facebook || configs.auth.twitter || configs.auth.github || configs.auth.google">
                            <div class="row mt-4">
                                <div class="col-12 text-center login-with-icons">
                                    <router-link v-if="configs.auth.smsOtpLogin" :to="{ name: 'login-sms-otp' }" class="btn btn-sm btn-info" v-b-tooltip.hover :title="$t('auth.login.login_using_sms_otp')"><i class="fas fa-mobile-alt"></i></router-link>

                                    <router-link v-if="configs.auth.emailOtpLogin" :to="{ name: 'login-email-otp' }" class="btn btn-sm btn-gmail" v-b-tooltip.hover :title="$t('auth.login.login_using_email_otp')"><i class="fas fa-envelope-open-text"></i></router-link>

                                    <template v-if="configs.auth.socialLogin && configs.auth.socialLoginProviders && configs.auth.socialLoginProviders.length">
                                        <a v-for="provider in configs.auth.socialLoginProviders" :key="provider" :href="`/auth/login/${provider}`" :class="`btn btn-sm ${btns[provider]}`" v-b-tooltip.hover :title="$t('auth.login.login_with', { attribute: provider})"><i :class="icons[provider]"></i></a>
                                    </template>
                                </div>
                            </div>

                            <div class="text-center">
                                <hr class="my-4">
                            </div>
                        </template>


                        <div class="row mt-4" v-if="configs.auth.resetPassword || configs.auth.registration">
                            <div :class="['col-12 text-center', {'col-md-6 text-md-left': configs.auth.registration}]" v-if="configs.auth.resetPassword">
                                <router-link :to="{ name: 'password' }" class="text-primary m-l-5"> <span class="font-weight-bold">{{ $t('auth.password.forgot_password') }}</span> </router-link>
                            </div>
                            <div :class="['col-12 text-center', {'col-md-6 text-md-right': configs.auth.resetPassword}]" v-if="configs.auth.registration">
                                <router-link :to="{ name: 'register' }" class="text-primary m-l-5"> <span class="font-weight-bold">{{ $t('auth.register.register_here') }}</span> </router-link>
                            </div>
                        </div>

                    </template>


                    <div class="text-center my-4 pt-4" v-if="configs && (!configs.system || !configs.system.mode)">
                        <base-dropdown tag="div" direction="up" menu-classes="show-dropdown-up" :position="configs.system && configs.system.direction === 'ltr' ? 'right' : 'left'">
                            <base-button slot="title" type="button" design="success" block class="text-uppercase" data-toggle="dropdown" role="button">
                                <span class="nav-link-inner--text">Auto Login As</span>
                                <i class="fas fa-chevron-up m-l-5"></i>
                            </base-button>

                            <template>
                                <button type="button" class="dropdown-item" @click="loginAs('admin')">Admin Role</button>
                                <button type="button" class="dropdown-item" @click="loginAs('user')">User Role</button>
                            </template>
                        </base-dropdown>
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
                    password: ''
                },
                formErrors: {},
                icons: {
                    'facebook': 'fab fa-facebook-f',
                    'twitter': 'fab fa-twitter',
                    'github': 'fab fa-github',
                    'google': 'fab fa-google',
                },
                btns: {
                    'facebook': 'btn-facebook',
                    'twitter': 'btn-twitter',
                    'github': 'btn-github',
                    'google': 'btn-google-plus',
                },
                isLoading: false
            }
        },
        computed: {
            ...mapGetters('config', [
                'configs',
                'vars'
            ]),
            ...mapGetters('user', [
                'twoFactorSet',
                'hasRole',
            ]),
        },
        methods: {
            ...mapActions('user', [
                'SetCSRF',
                'Login',
                'ResetTwoFactorSet',
            ]),
            submit() {
                this.isLoading = true
                let routeQuery = this.$route.query

                this.Login(this.formData)
                    .then(response => {
                        this.$toasted.success(response.message, this.$toastConfig)

                        if (this.configs.auth.twoFactorSecurity && this.twoFactorSet) {
                            this.$router.push({ name: 'authSecurity', query: routeQuery });
                            this.isLoading = false
                        } else {
                            let routeTo = response.reload ? { name: 'appDashboard', query: { reload: 1 } } : { name: 'appDashboard' }

                            if (routeQuery && routeQuery.ref && this.$router.resolve(routeQuery.ref)) {
                                routeTo = this.$router.resolve(routeQuery.ref)
                                    .route
                            }

                            if (this.hasRole('admin') && this.configs.system && this.configs.system.setupWizard) {
                                routeTo = { name: 'setup' }
                            }

                            this.ResetTwoFactorSet()
                                .then(() => {
                                    this.$router.push(routeTo)
                                })
                                .catch((error) => {
                                    this.isLoading = false
                                    this.formErrors = formUtil.handleErrors(error)
                                })
                        }
                    })
                    .catch(error => {
                        this.isLoading = false
                        this.formErrors = formUtil.handleErrors(error)
                    })
            },

            loginAs(role) {
                this.formData.email = role + '@' + role + '.com'
                this.formData.password = 'password'
                this.submit()
            },
        },
        mounted() {
            this.SetCSRF()
        }
    }

</script>
<style lang="scss" scoped>
    .login-with-icons {
        .btn {
            width: 30px;
            height: 30px;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            font-size: 0.9rem;
        }
    }

</style>
