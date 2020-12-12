import Vue from 'vue'
import VueRouter from 'vue-router'

Vue.use(VueRouter)

/* Layouts */
import AppLayout from '@views/layouts/app-layout'
import GuestLayout from '@views/layouts/guest-layout'
import LandingLayout from '@views/layouts/landing-layout'
import AppContentContainer from '@views/layouts/partials/app-content-container'

/* Router Modules */
import appRoutes from './modules/app'
import authRoutes from './modules/app/auth'
import liveRoutes from './modules/app/live'
import landingRoutes from './modules/app/landing'
import guestRoutes from './modules/guest'
import generalRoutes from './modules/general'

export const baseURL = '/app'

export const routesMap = [{
        path: '/',
        component: GuestLayout,
        redirect: { name: 'login' },
        meta: {
            isNotNav: true,
            validFor: 'guest',
        },
        children: [
            ...guestRoutes,
        ]
    },
    {
        path: '/',
        component: GuestLayout,
        meta: {
            isNotNav: true,
            validFor: 'public',
        },
        children: [
            ...generalRoutes,
        ]
    },
    {
        path: '/',
        component: LandingLayout,
        meta: {
            isNotNav: true,
            validFor: 'guest',
        },
        children: [
            ...landingRoutes,
        ]
    },
    {
        path: '/',
        component: LandingLayout,
        meta: {
            isNotNav: true,
            validFor: 'auth',
        },
        children: [
            ...liveRoutes,
        ]
    },
    {
        path: '/panel',
        name: 'App',
        meta: {
            validFor: 'auth',
        },
        redirect: { name: 'appDashboard' },
        component: AppLayout,
        children: [{
            path: '',
            meta: {
                title: '',
                isNavSection: true,
                isHiddenNav: true,
            },
            component: AppContentContainer,
            children: [
                ...appRoutes,
            ]
        }, ]
    },
    {
        path: '/panel',
        component: GuestLayout,
        meta: {
            isNotNav: true,
            validFor: 'auth',
        },
        children: [
            ...authRoutes,
        ]
    },
    {
        path: '*',
        meta: {
            isNotNav: true,
        },
        beforeEnter: (to, from, next) => {
            next({ name: 'error404', replace: true, query: { 'ref': to.fullPath, 'refFrom': from.fullPath } })
        }
    }
]

const router = new VueRouter({
    base: baseURL,
    linkActiveClass: 'active',
    mode: 'history',
    scrollBehavior(to, from, savedPosition) {
        if (savedPosition) {
            return savedPosition
        } else {

            const position = {}

            if (to.hash) {
                position.selector = to.hash

                if (document.querySelector(to.hash)) {
                    return position
                }

                // if the returned position is falsy or an empty object,
                // will retain current scroll position.
                return false
            }

            return new Promise(resolve => {
                if (to.matched.some(m => m.meta.hasOwnProperty('scrollToTop') && m.meta.scrollToTop === false)) {} else {
                    position.x = 0
                    position.y = 0
                }
                setTimeout(() => {
                    resolve(position)
                }, 500)
            })
        }
    },
    routes: routesMap
})

window.vueRouter = router

export default router
