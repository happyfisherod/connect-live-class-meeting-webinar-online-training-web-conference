<template>
    <avatar v-if="user && user.name" :username="user.name" :src="user.userThumb" :background-color="backgroundColor" :color="foregroundColor" :size="size"></avatar>
</template>

<script>
    import Avatar from 'vue-avatar'
    export default {
        name: "user-avatar",
        components: {
            Avatar,
        },
        props: {
            user: {
                type: Object,
                required: true
            },
            backgroundColor: {
                type: String,
                default: '#ffffff'
            },
            foregroundColor: {
                type: String,
                default: '#000000'
            },
            size: {
                type: Number,
                default: 40
            },
        }
    }
</script>