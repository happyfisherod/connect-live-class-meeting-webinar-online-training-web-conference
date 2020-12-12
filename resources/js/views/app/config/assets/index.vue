<template>
    <base-container boxed with-loader :is-loading="isLoading" :loader-color="vars.loaderColor">

        <div class="row">
            <div class="col-12 col-md-6 d-flex justify-content-center mb-4">
                <image-uploader url="/config/assets?type=logo" name-label="config.assets.logo" :existing-image="logo" placeholder="https://via.placeholder.com/250x150/f1f2f4/b1b2b4/?text=Your%20Logo" @uploaded="refreshConfig" remove-from-server @removed="refreshConfig" />
            </div>

            <div class="col-12 col-md-6 d-flex justify-content-center mb-4">
                <image-uploader url="/config/assets?type=logo_light" name-label="config.assets.logo_light" :existing-image="logoLight" placeholder="https://via.placeholder.com/250x150/313336/f1f2f4/?text=Your%20Logo" dark-bg @uploaded="refreshConfig" remove-from-server @removed="refreshConfig" />
            </div>

            <div class="col-12 col-md-6 d-flex justify-content-center mb-4">
                <image-uploader url="/config/assets?type=icon" name-label="config.assets.icon" :existing-image="icon" placeholder="https://via.placeholder.com/150x150/e1e2e4/b1b2b4/?text=Your%20Icon" @uploaded="refreshConfig" remove-from-server @removed="refreshConfig" />
            </div>

            <div class="col-12 col-md-6 d-flex justify-content-center mb-4">
                <image-uploader url="/config/assets?type=favicon" name-label="config.assets.favicon" :existing-image="favicon" placeholder="https://via.placeholder.com/150x150/e1e2e4/b1b2b4/?text=Your%20FavIcon" @uploaded="refreshConfig" remove-from-server @removed="refreshConfig" />
            </div>
        </div>
    </base-container>
</template>

<script>
    import ImageUploader from '@components/ImageUploader'
    import { mapGetters, mapActions } from 'vuex'

    export default {
        components: {
            ImageUploader,
        },
        data() {
            return {
                logo: '',
                logoLight: '',
                icon: '',
                favicon: '',
                isLoading: false
            }
        },
        computed: {
            ...mapGetters('config', [
                'configs',
                'vars',
            ]),
        },
        methods: {
            ...mapActions('config', [
                'GetConfig',
            ]),
            handleUploadError(errorMessage) {
                this.$toasted.error(errorMessage, this.$toastConfig.error)
            },
            getInitialData() {
                const imageObj = this.configs.assets

                if(imageObj) {
                    this.logo      = imageObj.logo || ''
                    this.logoLight = imageObj.logoLight || ''
                    this.icon      = imageObj.icon || ''
                    this.favicon   = imageObj.favicon || ''
                }
            },
            refreshConfig() {
                this.isLoading = true
                this.GetConfig()
                    .then((response) => {
                        const imageObj = this.configs.assets

                        if(imageObj) {
                            this.logo      = imageObj.logo || ''
                            this.logoLight = imageObj.logoLight || ''
                            this.icon      = imageObj.icon || ''
                            this.favicon   = imageObj.favicon || ''
                        }
                        this.isLoading = false
                        this.$toasted.success(response.message, this.$toastConfig.success)
                    })
                    .catch(error => {
                        this.isLoading = false
                        this.formErrors = formUtil.handleErrors(error)
                    })
            },
        },
        mounted() {
            this.getInitialData()
        },
    }

</script>
