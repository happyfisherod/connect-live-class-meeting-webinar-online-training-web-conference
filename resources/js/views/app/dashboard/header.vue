<template>
    <app-dashboard-header>
        <div class="header-body min-height-150px">
            <animated-loader :is-loading="isLoading && !(others.stats && others.stats.length)" :loader-color="vars.colors.white" overlay-color="transparent" />
            <!-- Card stats -->

            <div class="row" v-if="others.stats && others.stats.length">
                <div class="col-12 col-sm-6 col-md-3" v-for="stat in others.stats" :key="stat.label">
                    <stat-box :is-fetching="isLoading" :stat="stat" />
                </div>
            </div>
        </div>

    </app-dashboard-header>
</template>

<script>
    import AppDashboardHeader from '@views/layouts/partials/app-dashboard-header'
    import { mapGetters, mapActions } from 'vuex'
    import StatBox from './widgets/StatBox'

    export default {
        components: {
            AppDashboardHeader,
            StatBox,
        },
        data() {
            return {
                isLoading: false,
            }
        },
        computed: {
            ...mapGetters('config', [
                'vars',
            ]),
            ...mapGetters('common', [
                'others',
            ]),
        },
        methods: {
            ...mapActions('common', [
                'Custom',
                'SetOthers',
            ]),
            getInitialData() {
                this.isLoading = true
                this.Custom({
                        url: 'dashboard/stats',
                        method: 'get'
                    })
                    .then(response => {
                        this.SetOthers({
                            stats: response
                        })
                        this.isLoading = false
                    })
                    .catch(error => {
                        this.isLoading = false
                        formUtil.handleErrors(error)
                    })
            },
        },
        mounted() {
            this.getInitialData()
        },
        beforeRouteEnter(to, from, next) {
            next(vm => {
                vm.$store.state.config.ui.appIsLoading = false
            })
        },
    };

</script>

<style lang="scss" scoped>
    @import '~@js/core/assets/scss/imports.scss';
    @import "~@js/core/assets/scss/partials/palettes";

    // .main {
    //     padding-top: $side-margin;
    //     padding-left: $side-margin;
    //     padding-right: $side-margin;
    //     transition: #{$transition-all-ease};
    //     // transform: translate3d(0, 0, 0);
    // }

    .header-body {
        margin-left: -$margin-common;
        margin-right: -$margin-common;
        margin-bottom: 90px;
        margin-top: 0px;
    }

    @each $key,
    $value in $default-palette {
        [data-top-navbar-color="#{$key}"] {
            & .page-header {
                background-color: map-get($value, "background-color") !important;
                color: map-get($value, "foreground-color") !important;
            }
        }
    }

</style>
