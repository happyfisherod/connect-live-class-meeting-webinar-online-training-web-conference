<template>
    <base-container boxed with-loader min-height="full" :is-loading="isLoading || !product.currentVersion" :loader-color="vars.loaderColor" class="d-flex align-items-center">
        <div class="text-center mt-2" v-if="product.currentVersion === product.latestVersion">
            <h3 class="text-muted mb-3">No update available!</h3>
            <p class="text-muted">We are constantly working on new features and fixes. We release new update after completing the development and thorough testing. Kindly check later for new updates.</p>
            <div class="mt-5 mt-2">
                <router-link :to="{ name: 'appDashboard' }" class="btn btn-primary">{{ $t('general.go_to_dashboard') }}</router-link>
            </div>
        </div>

        <div v-else-if="!isProcessing">
            <div v-html="updateTips"></div>

            <div class="row mt-4">
                <div class="col-12 col-md-4">
                    <div class="label-group">
                        <label class="text-muted">Version Available</label>
                        <p class="font-weight-bold">{{ product.nextReleaseVersion }}</p>
                    </div>
                </div>
                <div class="col-12 col-md-4">
                    <div class="label-group">
                        <label class="text-muted">Date of Release</label>
                        <p class="font-weight-bold">{{ product.nextReleaseDate | moment(vars.defaultDateFormat) }}</p>
                    </div>
                </div>
                <div class="col-12 col-md-4">
                    <div class="label-group">
                        <label class="text-muted">Update Size</label>
                        <p class="font-weight-bold">{{ getFileSize(product.nextReleaseSize) }}</p>
                    </div>
                </div>
            </div>

            <hr class="my-4">

            <div v-html="product.nextReleaseChangeLog"></div>

            <div class="row">
                <div class="col-12 col-md-6" v-if="!isDownloaded">
                    <base-button type="button" design="info" block class="my-4" key="download" @click="confirmDownload(0)">{{ $t('product.download') }}</base-button>
                </div>
                <div class="col-12 col-md-6" v-if="!isDownloaded">
                    <base-button type="button" design="success" block class="my-4" key="download-update" @click="confirmDownload(1)">{{ $t('product.update_download') }}</base-button>
                </div>
                <div class="col-12 col-md-12 mt-5" v-if="isDownloaded">
                    <base-button type="button" design="info" block key="direct-update" @click="confirmUpdate()">{{ $t('product.update_download') }}</base-button>
                </div>
            </div>

        </div>

        <div v-else>
            <p class="text-center">Don't perform any action till we are performing update!</p>
            <p class="text-center" v-if="is_downloading">Update Size ({{ getFileSize(product.nextReleaseSize) }}) - Downloading...</p>
            <p class="text-center" v-if="is_updating">Updating...</p>
            <base-button type="button" design="info" block class="mt-5" key="update" @click="confirmUpdate()">{{ $t('general.update') }}</base-button>
        </div>
    </base-container>
</template>

<script>
    import swtAlert from '@js/core/configs/sweet-alert'
    import { mapGetters, mapActions } from 'vuex'
    import { bytesToFileSize } from '@js/core/utils/formatter'

    export default {
        data() {
            return {
                isLoading: false,
                isProcessing: false,
                isDownloading: false,
                isUpdating: false,
            }
        },
        computed: {
            ...mapGetters('config', [
                'configs',
                'vars',
            ]),
            ...mapGetters('product', [
                'product',
                'updateTips',
                'isDownloaded',
            ]),
            formData(){
                return {
                    build: this.product.nextReleaseBuild,
                    version: this.product.nextReleaseVersion
                }
            },
        },
        methods: {
            ...mapActions('product', [
                'PostSupport',
            ]),
            getFileSize(size){
                return bytesToFileSize(size)
            },
            confirmUpdate(){
                swtAlert({
                        title: 'Are you sure?',
                        text: "This will update this application to the latest version.",
                        type: 'warning',
                        showCancelButton: true,
                        confirmButtonText: 'Yes, update!',
                        cancelButtonText: 'No, cancel!'
                    })
                    .then((result) => {
                        if (result.value) {
                            this.update()
                        }
                    }) 
            },
            confirmDownload(action){
                const message = action === 0 ? "This will download the latest version of the application." : "This will download and update the application to the latest version."
                swtAlert({
                        title: 'Are you sure?',
                        text: message,
                        type: 'warning',
                        showCancelButton: true,
                        confirmButtonText: 'Yes, update!',
                        cancelButtonText: 'No, cancel!'
                    })
                    .then((result) => {
                        if (result.value) {
                            this.download(action)
                        }
                    }) 
            },
            download(action) {
                // this.isLoading = true
                this.isProcessing = true
                this.isDownloading = true
                this.DownloadApp()
                    .then(response => {
                        this.isDownloading = false
                        this.$toasted.success(response.message, this.$toastConfig.success)
                        if(action) {
                            this.update()
                        } else {
                            this.isProcessing = false
                            // this.isLoading = false
                        }
                    })
                    .catch(error => {
                        this.isLoading = false
                        // console.error(error)
                        this.$toasted.error(error, this.$toastConfig.error)
                        this.isProcessing = false
                        this.isDownloading = false
                    })
            },
            update() {
                // this.isLoading = true
                this.isProcessing = true
                this.isUpdating = true
                this.UpdateApp(this.formData)
                    .then(response => {
                        this.$toasted.success(response.message, this.$toastConfig.success)
                        setTimeout(() => {
                            location.reload()
                        }, 2000)
                    })
                    .catch(error => {
                        this.isLoading = false
                        // console.error(error)
                        this.$toasted.error(error, this.$toastConfig.error)
                        this.isProcessing = false
                        this.isUpdating = false
                    })
            },
        }
    }

</script>
