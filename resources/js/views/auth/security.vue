<template>
    <div class="guest-page">
        <box>
            <animated-loader :is-loading="isLoading" :loader-color="vars.loaderColor" />

            <guest-header>
                <h5>{{ $t('auth.security.page_title') }}</h5>
            </guest-header>

            <section role="main">

                <form @submit.prevent="submit">
                    <base-input auto-focus class="mb-3" :label="$t('auth.security.props.two_factor_code')" type="text" name="twoFactorCode" v-model="formData.twoFactorCode" addon-left-icon="fas fa-key" :error.sync="formErrors.twoFactorCode">
                    </base-input>

                    <div class="text-center">
                        <base-button type="submit" design="primary" block class="my-4 text-lg">{{ $t('general.proceed') }}</base-button>
                    </div>

                    <div class="form-group m-b-0">
                        <div class="col-sm-12 text-center">
                            <h6 class="text-uppercase">{{ $t('general.or') }}</h6>
                            <p>
                                <base-button type="button" @click="logout" design="link"><i class="fas fa-power-off"></i><span class="font-weight-bold">{{ $t('auth.logout') }}</span></base-button>
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
                    twoFactorCode: '',
                },
                formErrors: {},
                isLoading: false
            }
        },
        computed: {
            ...mapGetters('config', [
                'configs',
                'vars',
            ]),
            ...mapGetters('user', [
                'twoFactorSet',
            ]),
        },
        mounted() {
            if (this.configs.system && !this.configs.system.mode) {
                this.formData.twoFactorCode = 123456;
            }
        },
        methods: {
            ...mapActions('user', [
                'Logout',
                'CheckTwoFactorCode',
            ]),
            submit() {
                this.isLoading = true
                let routeQuery = this.$route.query

                this.CheckTwoFactorCode({
                        twoFactorCode: this.formData.twoFactorCode
                    })
                    .then(response => {
                        let routeTo = { name: 'appDashboard' }

                        if(routeQuery && routeQuery.ref && this.$router.resolve(routeQuery.ref)) {
                            routeTo = this.$router.resolve(routeQuery.ref).route
                        }
                        
                        this.$toasted.success(this.$t(response.message), this.$toastConfig)
                        this.$router.push(routeTo)
                    })
                    .catch(error => {
                        this.isLoading = false
                        // console.error(error)
                        this.$toasted.error(this.$t('auth.security.invalid_code'), this.$toastConfig)
                    })
            },

            logout() {
                this.isLoading = true
                this.Logout()
                    .then(() => {
                        this.$router.push({ name: 'login' })
                    })
            },
        },
    }

</script>
<style lang="scss" scoped>


</style>
