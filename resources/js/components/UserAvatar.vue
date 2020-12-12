<template>
    <span class="user-avatar">
        <img src="@images/avatars/male-transparent.png" />
    </span>
</template>

<script>
export default {}
</script>
<style lang="scss" scoped>
    .user-avatar {
        display: flex;
        align-items: center;
        justify-content: center;
        width: 40px;
        height: 40px;
        overflow: hidden;

        img {
            width: 100%;
        }
        &.outline {
            border: 1px solid #ffffff;
        }
        &.bg {
            background: #ffffff;
        }
    }
</style>