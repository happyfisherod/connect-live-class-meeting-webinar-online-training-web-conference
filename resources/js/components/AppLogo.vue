<template>
    <a href="/" :class="['logo', `${place}-logo`, `${size}-logo`, orgLogo ? 'org-logo' : 'app-logo', inline ? 'inline-logo' : '']">
        <img class="logo-icon" v-if="orgLogo" :src="orgLogo" :alt="appTitle" />
        <template v-else>
            <span class="logo-text" :title="appTitle">{{ appLogoText }}</span>
        </template>
    </a>
</template>

<script>
    import { mapGetters } from 'vuex'
    export default {
        props: {
            place: {
                type: String,
                default: 'normal'
            },
            size: {
                type: String,
                default: 'normal'
            },
            appLogo: {
                type: Boolean,
                default: false
            },
            inline: {
                type: Boolean,
                default: false
            },
        },
        data() {
            return {
                appLogoText: process.env.MIX_APP_NAME,
            }
        },
        computed: {
            ...mapGetters('config', [
                'configs',
                'uiConfigs',
            ]),
            orgLogo() {
                if(this.appLogo || !this.configs.assets) {
                    if( this.place === 'navbar' || this.place === 'sidebar' || this.place === 'dark' ) {
                        return '/images/logo-light.png'
                    }
                    return '/images/logo.png'
                }
                
                let finalLogo = this.configs.assets.logo || '/images/logo.png'

                if(this.configs.assets.logoLight) {
                    if( (this.place === 'navbar' && this.uiConfigs.topNavbarLogoLight) || (this.place === 'sidebar' && this.uiConfigs.leftSidebarLogoLight) || this.place === 'dark' ) {
                        finalLogo = this.configs.assets.logoLight
                    }
                }
                return finalLogo
            },
            appTitle() {
                return this.configs.basic ? this.configs.basic.orgName : process.env.MIX_APP_NAME
            },
        },
    }

</script>
