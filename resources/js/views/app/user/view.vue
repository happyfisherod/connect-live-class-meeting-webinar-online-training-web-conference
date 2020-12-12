<template>
    <profile-page :is-loading="isLoading" :loader-color="vars.loaderColor">

        <template #sidebarMainContent>
            <profile-card v-if="entity" :name="entity.profile.name" :gender="entity.profile.gender" :image="entity.profile.avatar" data-card-color="whitish" :horizontal="false" />
        </template>



        <template #mainContent>
            <base-container boxed with-loader has-footer min-height="full" :is-loading="isLoading" :loader-color="vars.loaderColor">

                <template v-if="entity">
                    <div class="row">
                        <div class="col-12 col-md-6 mb-3">
                            <view-single :label="$t('user.props.name')" :value="entity.profile.name" />
                        </div>
                        <div class="col-12 col-md-6 mb-3">
                            <view-single :label="$t('user.props.gender')" :value="entity.profile.gender" showIfExists="name" />
                        </div>
                        <div class="col-12 col-md-6 mb-3">
                            <view-single :label="$t('user.props.email')" :value="entity.email" />
                        </div>
                        <div class="col-12 col-md-6 mb-3">
                            <view-single :label="$t('user.props.birth_date')" :value="entity.profile.birthDate | moment(vars.defaultDateFormat)" />
                        </div>
                    </div>
                </template>

                <div class="form-footer mt-5">
                    <div class="left-side">
                        <base-button type="button" design="light" @click="$router.back()" tabindex="-1"><i class="fas fa-chevron-left"></i> {{ $t('general.back') }}</base-button>
                    </div>
                </div>
            </base-container>
        </template>

    </profile-page>
</template>

<script>
    import view from '@mixins/view'
    import ProfilePage from '@components/ProfilePage'
    import ProfilePageSidebox from '@components/ProfilePageSidebox'
    import * as headerMixins from '@mixins/header'

    export default {
        extends: view,
        components: {
            ProfilePage,
            ProfilePageSidebox,
        },
        data() {
            return {
                initUrl: 'users',
                dataTitle: $t('user.user'),
                fallBackRoute: 'appUserList',
                permissionsRequired: {
                    add: 'create-user',
                    edit: 'edit-user',
                },
                routesRequired: {
                    add: 'appUserAdd',
                    edit: 'appUserEdit',
                },
            }
        },
        methods: {
            changeStatus(status) {
                formUtil.confirmAction()
                    .then((result) => {
                        if (result.value) {
                            this.isLoading = true
                            let data = {
                                status
                            }

                            this.Custom({
                                    url: `/${this.initUrl}/${this.uuid}/status`,
                                    method: 'post',
                                    data
                                })
                                .then(response => {
                                    this.isLoading = false
                                    this.getInitialData()
                                })
                                .catch(error => {
                                    this.isLoading = false
                                    formUtil.handleErrors(error)
                                })
                        } else {
                            result.dismiss === Swal.DismissReason.cancel
                        }
                    })
            }
        },
    }

</script>
