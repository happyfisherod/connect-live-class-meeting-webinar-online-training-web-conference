import Vue from 'vue'
import Vuex from 'vuex'
import CreatePersistedState from 'vuex-persistedstate'

import vars from '@js/vars'

// loading store for all the modules
import config from './modules/config'
import errorLog from './modules/error-log'
import navigation from './modules/navigation'
import user from './modules/user'
import search from './modules/search'
import todo from './modules/todo'
import common from './modules/common'
import product from './modules/product'

// loading other getters, actions and mutations
import getters from './getters'
import actions from './actions'
import mutations from './mutations'

Vue.use(Vuex)

if(window.localStorage) {
    const existingVersion = window.localStorage.getItem(vars.localStorageVersionKey)
    if(vars.appVersion !== existingVersion) {
        window.localStorage.removeItem(vars.localStorageKey)
    }
    window.localStorage.setItem(vars.localStorageVersionKey, vars.appVersion)
}

const store = new Vuex.Store({
    state: {},
    modules: {
        config,
        errorLog,
        navigation,
        user,
        search,
        todo,
        common,
        product,
    },
    getters,
    actions,
    mutations,
    plugins: [
        CreatePersistedState({
            key: vars.localStorageKey,
        })
    ]
})

export default store
