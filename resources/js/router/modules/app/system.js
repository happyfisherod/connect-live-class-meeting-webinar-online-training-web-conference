import store from '@js/store'

export default [{
        path: 'product',
        name: 'appProduct',
        redirect: { name: 'appProductAbout' },
        meta: {
            title: 'product.product',
            icon: 'product',
            roles: ['admin'],
            isNotNav: true,
        },
        component: () =>
            import ('@views/app/product/index' /* webpackChunkName: "js/app/product/index" */ ),
        children: [{
                path: 'update',
                name: 'appProductUpdate',
                meta: {
                    title: 'product.update.product_update',
                },
                component: () =>
                    import ('@views/app/product/update' /* webpackChunkName: "js/app/product/update" */ ),
            }
        ]
    },
    {
        path: 'license',
        name: 'license',
        meta: {
            title: 'product.license.verification',
            roles: ['admin'],
            isNotNav: true,
        },
        component: () =>
            import ('@views/app/license/index' /* webpackChunkName: "js/app/license/index" */ ),
        beforeEnter: ((to, from, next) => {
            const configs = store.getters['config/configs']
            if (configs.license) {
                next('/')
            } else {
                next()
            }
        })
    },
    // {
    //     path: 'setup',
    //     name: 'setup',
    //     meta: {
    //         title: 'product.setup_title',
    //         roles: ['admin'],
    //         isNotNav: true,
    //     },
    //     component: () =>
    //         import ('@views/app/setup/index' /* webpackChunkName: "js/app/setup/index" */ )
    // },
]
