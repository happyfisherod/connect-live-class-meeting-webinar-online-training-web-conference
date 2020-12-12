<template>
    <header class="print-header print-header-simple">
        <div class="row">
            <div class="col-5">
                <app-logo place="print-header" />
            </div>

            <div class="col-7 text-right contact-details" v-if="basic">
                <p v-if="basic.addressLine1">{{ basic.addressLine1 }}</p>
                <p v-if="basic.addressLine2">{{ basic.addressLine2 }}</p>
                <p v-if="region">{{ region }}</p>
                <h6 v-if="basic.phone || basic.email">
                    <span v-if="basic.phone" class="">{{ $t('config.basic.phone') }}: <span class="font-weight-700">{{ basic.phone }}</span></span><span v-if="basic.email" class="pre-comma">{{ $t('config.basic.email') }}: <span class="font-weight-700">{{ basic.email }}</span></span>
                </h6>
            </div>
        </div>
    </header>
</template>

<script>
    import AppLogo from '@components/AppLogo'
    import { mapGetters } from 'vuex'

    export default { 
        components: {
            AppLogo,
        },
        data() {
            return {
            }
        },
        computed: {
            ...mapGetters('config', [
                'configs',
            ]),
            basic() {
                return this.configs.basic
            },
            address() {
                let address = this.basic.addressLine1
                address = this.basic.addressLine2 ? (address ? `${address}, ${this.basic.addressLine2}` : this.basic.addressLine2) : address
                return address
            },
            region() {
                let region = this.basic.city
                region = region ? (this.basic.zipcode ? `${region} - ${this.basic.zipcode}` : region) : ''
                region = this.basic.state ? (region ? `${region}, ${this.basic.state}` : this.basic.state) : region
                region = this.basic.country ? (region ? `${region}, ${this.basic.country}` : this.basic.country) : region
                return region
            },
        }
    }
</script>
