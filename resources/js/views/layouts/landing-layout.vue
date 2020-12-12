<template>
    <div class="landing-layout">
        <transition appear name="fade-transform" mode="out-in">
            <router-view></router-view>
        </transition>
        <!-- <notifications group="landing" /> -->
    </div>
</template>

<script>
    export default {}
</script>

<style lang="scss">
    .landing-layout {
        width: 100%;
        min-height: 100%;
        display: flex;
        align-items: center;
        justify-content: center;
        flex-direction: column;
        position: relative;
    }

</style>
