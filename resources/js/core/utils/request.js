import axios from 'axios'
import NProgress from 'nprogress'
import store from '@js/store'
import { handleErrors } from './form'
import { formatKeysToCamelCase, formatKeysToSnakeCase } from './formatter'

function logout(calledUrl, callback) {
    if(calledUrl === '/auth/logout') {
        callback()
        return
    }
    store.dispatch('user/Logout').then(() => {
        callback()
    })
}


axios.defaults.headers.common['X-Requested-With'] = 'XMLHttpRequest';
axios.defaults.withCredentials = true;

// import toastConfig from '@core/configs/toast'

// const csrfToken = document.head.querySelector('meta[name="csrf-token"]')
const calculatePercentage = (loaded, total) => (Math.floor(loaded * 1.0) / total)

// if (csrfToken) {
//     axios.defaults.headers.common['X-CSRF-TOKEN'] = csrfToken.content
// } else {
//     console.error('CSRF token not found: https://laravel.com/docs/csrf#csrf-x-csrf-token')
// }

// create an axios instance
const instance = axios.create({
    // baseURL: process.env.BASE_API, // api base_url
    baseURL: '/api',
    withCredentials: true,
    // transformResponse: [function (data) { // if you want to transform the incoming data inside response
    //     return data;
    // }]
});

instance.defaults.headers.common['X-Requested-With'] = 'XMLHttpRequest';
instance.defaults.withCredentials = true

// to increase NProgress percentage
instance.defaults.onDownloadProgress = e => {
    const percentage = calculatePercentage(e.loaded, e.total)
    NProgress.set(percentage)
}

// request interceptor
instance.interceptors.request.use(
    config => {
        // console.log('interceptors request', config)
        config.headers['X-Requested-With'] = 'XMLHttpRequest'

        // if(config.url.indexOf('?') !== -1) {
        //     let urlArr = config.url.split('?')
        //     urlArr[1] = formatKeysToSnakeCase(urlArr[1])
        //     config.url = urlArr.join('?')
        // }

        if(config.params) {
            config.params = formatKeysToSnakeCase(config.params)
        }

        if(!config.upload && config.data) {
            config.data = formatKeysToSnakeCase(config.data)
        }
        return config
    },
    error => {
        // debugger
        NProgress.done(true)
        // console.log('err' + error) // for debug
        handleErrors(error)
        return Promise.reject(error)
    })

// respone interceptor
instance.interceptors.response.use(
    response => {
        NProgress.done(true)
        // console.log('interceptors response', response)
        if((typeof response.data === 'object' || response.data.isArray) && response.data !== null) {
            return formatKeysToCamelCase(response.data)
        }
        return response.data
    },
    error => {
        let err = {}
        // debugger
        NProgress.done(true)

        err.response = error.response
        let calledUrl = err.response.config && err.response.config.url ?  err.response.config.url : null

        const errorStatus = err.response.status

        if(errorStatus === 400 || errorStatus === 401) {

            handleErrors(err)
            // console.log('err' + error) // for debug
            logout(calledUrl, () => {
                vueRouter.push({ name: 'login' })
            })
            // location.reload()
            
        } else if(errorStatus === 403 || errorStatus === 404 || errorStatus === 500) {

            // handleErrors(error)
            // console.log('err' + error) // for debug
            return Promise.reject(formatKeysToCamelCase(err))

        } else if(errorStatus === 406) {

            // handleErrors(err)
            // console.log('err' + error) // for debug

            const errorData = err.response.data
            try {
                if(errorData.hasOwnProperty('cmd')) {
                    const command = errorData.cmd
                    if(command === 'logout') {
                        logout(calledUrl, () => {
                            vueRouter.push({ name: 'login' })
                        })
                        return Promise.reject(formatKeysToCamelCase(err))
                    } else if(command === 'reload') {
                        location.reload()
                        return Promise.reject(formatKeysToCamelCase(err))
                    } else if(command === 'logout&hardReload') {
                        logout(calledUrl, () => {
                            location.reload(true)
                        })
                        return Promise.reject(formatKeysToCamelCase(err))
                    } else if(command === 'redirectTo') {
                        if(vueRouter.currentRoute.name !== errorData.path)
                        {
                            vueRouter.push({ name: errorData.path })
                        }
                    } else {
                        return Promise.reject(formatKeysToCamelCase(err))
                    }
                } else {
                    return Promise.reject(formatKeysToCamelCase(err))
                }
            } catch(e){
                 Promise.reject(e)
            }

        } else {

            // handleErrors(error)
            // console.log('err' + err.response.data) // for debug 
            return Promise.reject(formatKeysToCamelCase(err))

        }
    })

export default instance
export { axios }