import Vue from 'vue'
import { v4 as uuid } from 'uuid'

// Importing Core
import Core from '@core'

// Importing other components
import SearchUser from '@components/SearchUser'
import ProfileButtons from '@components/ProfileButtons'
import ProfileCard from '@components/ProfileCard'
import SmallProfileCard from '@components/SmallProfileCard'
import ViewUser from '@components/ViewUser'
import SearchTag from '@components/SearchTag'
import TableRowActions from '@components/TableRowActions'
import KeepAddingForm from '@components/KeepAddingForm'

import './service-worker/register'


// Binding few libraries for their global presence
window.Vue = Vue
window.uuid = uuid

Vue.use(Core)

// Registering Components
Vue.component(SearchUser.name, SearchUser)
Vue.component(ProfileButtons.name, ProfileButtons)
Vue.component(ProfileCard.name, ProfileCard)
Vue.component(SmallProfileCard.name, SmallProfileCard)
Vue.component(ViewUser.name, ViewUser)
Vue.component(SearchTag.name, SearchTag)
Vue.component(KeepAddingForm.name, KeepAddingForm)
Vue.component(TableRowActions.name, TableRowActions)

// Setting up Vue Router
import './router/setup'

Vue.config.productionTip = false
Vue.config.silent = true
Vue.config.devtools = false
