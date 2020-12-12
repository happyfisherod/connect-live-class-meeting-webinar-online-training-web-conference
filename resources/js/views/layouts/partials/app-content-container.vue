<template>
    <transition appear name="fade" mode="out-in">
        <div class="row">
            <div class="col main">
                <div class="page">
                    <router-view name="header">
                    </router-view>

                    <transition appear name="fade-transform" mode="out-in">
                        <router-view />
                    </transition>
                </div>
            </div>
        </div>
    </transition>
</template>

<script>
    export default {
        name: 'AppContentContainer',
        beforeRouteEnter(to, from, next) {
            next(vm => {
                vm.$store.state.config.appIsLoading = false
            })
        },
    }

</script>

<style lang="scss" scoped>
    @import '~@js/core/assets/scss/imports.scss';

    // .main {
    //     padding-top: $side-margin;
    //     padding-left: $side-margin;
    //     padding-right: $side-margin;
    //     transition: #{$transition-all-ease};
    //     // transform: translate3d(0, 0, 0);
    //     margin-bottom: 5rem;
    // }

    @include media-breakpoint-down(sm) {
        .main {
            margin-top: $side-margin * 2;
        }
    }
</style>
