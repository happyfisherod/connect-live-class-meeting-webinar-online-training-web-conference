import './extend-js'

// Importing third party libraries
import moment from 'moment'
import vueMoment from 'vue-moment'
// import Notifications from 'vue-notification'
import Toasted from 'vue-toasted'
import vuescroll from 'vuescroll/dist/vuescroll-native'
import VueLazyload from 'vue-lazyload'
import { ModalPlugin } from 'bootstrap-vue'
import fullscreen from 'vue-fullscreen'

// Importing configs of third party libraries
import toastConfig from './configs/toast'
import { swtAlert } from './configs/sweet-alert'
import vuescrollConfig from './configs/vuescroll'

// Importing third party stylesheets
import '@fortawesome/fontawesome-free/css/all.css'
import 'nprogress/nprogress.css'
import 'animate.css/animate.min.css'
import 'vue-multiselect/dist/vue-multiselect.min.css'
import 'flatpickr/dist/flatpickr.css'
import 'vuescroll/dist/vuescroll.css'
import 'bootstrap-vue/dist/bootstrap-vue.css'

// Importing required image assets
import lazyloadError from '@images/plugin/lazyload-error.png'
import lazyload from '@images/plugin/lazyload.svg'

// Importing stylesheets
import './assets/scss/core.scss'

import * as formUtil from './utils/form'
import components from './components'
import directives from './directives'
import plugins from './plugins'
import filters from './filters'


// Few settings to be done
window.moment = moment
window.toastConfig = toastConfig
window.swtAlert = swtAlert
window.formUtil = formUtil
moment.defaultFormat = 'YYYY-MM-DD'


export default {
  install(Vue) {
    Vue.prototype.trans = window.trans
    Vue.prototype.$t = window.trans
    // Register third party libraries
    Vue.use(vueMoment, { moment })
    // Vue.use(Notifications)
    Vue.use(Toasted)
    Vue.use(fullscreen)
    Vue.use(vuescroll, { ops: vuescrollConfig })
    Vue.use(VueLazyload, {
        preLoad: 1.4,
        error: lazyloadError,
        loading: lazyload,
        attempt: 1
    })
    Vue.use(ModalPlugin)

    Vue.use(components)
    Vue.use(directives)
    Vue.use(plugins)
    Vue.use(filters)
    
    Vue.prototype.$toastConfig = window.toastConfig
  }
}
