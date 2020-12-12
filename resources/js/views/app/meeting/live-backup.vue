<template>
    <base-container with-loader :is-loading="isLoading" :loader-color="vars.loaderColor" :overlay-color="pageConfigs.isDark ? 'dark' : 'light'" :class="['meeting-page', {'dark': pageConfigs.isDark}]">

        <div v-if="!duplicateTab" class="meeting-header">

            <div class="logo-wrapper">
                <app-logo :place="pageConfigs.isDark ? 'dark':'light'" size="sm" />
            </div>

            <div class="meeting-actions">
                <button type="button" class="btn action" @click="$router.push({ name: 'appMeetingList'})" v-b-tooltip.hover.d500 :title="$t('general.back')"><i class="fas fa-chevron-left"></i></button>

                <div class="separator"></div>

                <template v-if="entity && entity.status && videoList.length">
                    <template v-if="localVideo">
                        <button v-if="pageConfigs.enableVideo" type="button" class="btn action enabled-text" @click="toggleVideo" v-b-tooltip.hover.d500 :title="$t('meeting.mute_video')"><i class="fas fa-video"></i></button>
                        <button v-else type="button" class="btn action disabled-text" @click="toggleVideo" v-b-tooltip.hover.d500 :title="$t('meeting.unmute_video')"><i class="fas fa-video-slash"></i></button>

                        <button v-if="pageConfigs.enableAudio" type="button" class="btn action enabled-text" @click="toggleAudio" v-b-tooltip.hover.d500 :title="$t('meeting.mute_audio')"><i class="fas fa-microphone"></i></button>
                        <button v-else type="button" class="btn action disabled-text" @click="toggleAudio" v-b-tooltip.hover.d500 :title="$t('meeting.unmute_audio')"><i class="fas fa-microphone-slash"></i></button>
                    </template>


                    <button v-if="localScreenStreamid" type="button" class="btn action" @click="stopSharingScreen" v-b-tooltip.hover.d500 :title="$t('meeting.stop_sharing_screen')"><i class="fas fa-minus-square"></i></button>

                    <button v-else type="button" class="btn action" @click="shareScreen" v-b-tooltip.hover.d500 :title="$t('meeting.share_screen')"><i class="fas fa-desktop"></i></button>

                    <div class="separator"></div>

                    <button type="button" class="btn action" @click="endMeeting" v-b-tooltip.hover.d500 :title="$t('meeting.end_meeting')"><i class="fas fa-calendar-times"></i></button>

                    <button type="button" class="btn action" @click="getOffline" v-b-tooltip.hover.d500 :title="$t('meeting.leave_meeting')"><i class="fas fa-sign-out-alt"></i></button>
                </template>

                <button v-if="entity && entity.config && entity.config.enableComments" type="button" :class="['btn action', {'pulse': newComments}]" @click="toggleComments" v-b-tooltip.hover.d500 :title="$t((pageConfigs.showComments ? 'global.hide' : 'global.show'), { attribute: $t('comment.comments')})"><i :class="[{'fas fa-comment-slash': pageConfigs.showComments}, {'far fa-comment': !pageConfigs.showComments}]"></i></button>

                <button type="button" class="btn action" @click="toggleAgenda" v-b-tooltip.hover.d500 :title="$t((pageConfigs.showAgenda ? 'global.hide' : 'global.show'), { attribute: $t('general.agenda')})"><i class="fas fa-quote-left"></i></button>

                <div class="separator"></div>

                <button type="button" class="btn action" @click="toggleDark" v-b-tooltip.hover.d500 :title="$t('global.switch', { attribute: pageConfigs.isDark ? $t('config.ui.light') : $t('config.ui.dark')})"><i class="fas fa-adjust"></i></button>
            </div>

            <div class="meeting-actions-mobile">
                <base-dropdown tag="div" direction="down" menu-classes="show-dropdown-up" position="right" design="gray-darker" size="md">

                    <base-button slot="title" type="button" data-toggle="dropdown" role="button" size="md" design="transparent"><i class="fas fa-ellipsis-v"></i></base-button>

                    <a class="dropdown-item" @click.stop="$router.push({ name: 'appMeetingList'})"><i class="fas fa-chevron-left"></i> {{ $t('general.back') }}</a>

                    <template v-if="entity && entity.status && videoList.length">
                        <a class="dropdown-item" @click.stop="endMeeting"><i class="fas fa-calendar-times"></i> {{ $t('meeting.end_meeting') }}</a>

                        <a class="dropdown-item" @click.stop="getOffline"><i class="fas fa-sign-out-alt"></i> {{ $t('meeting.leave_meeting') }}</a>

                        <a v-if="localScreenStreamid" class="dropdown-item" @click.stop="stopSharingScreen"><i class="fas fa-minus-square"></i> {{ $t('meeting.stop_sharing_screen') }}</a>

                        <a v-else class="dropdown-item" @click.stop="shareScreen"><i class="fas fa-desktop"></i> {{ $t('meeting.share_screen') }}</a>
                    </template>

                    <a v-if="entity && entity.config && entity.config.enableComments" class="dropdown-item" @click.stop="toggleComments"><i :class="[{'fas fa-comment-slash': pageConfigs.showComments}, {'far fa-comment': !pageConfigs.showComments}]"></i> {{ $t((pageConfigs.showComments ? 'global.hide' : 'global.show'), { attribute: $t('comment.comments')}) }}</a>

                    <a class="dropdown-item" @click.stop="toggleAgenda"><i class="fas fa-quote-left"></i> {{ $t((pageConfigs.showAgenda ? 'global.hide' : 'global.show'), { attribute: $t('general.agenda')}) }}</a>

                    <a class="dropdown-item" @click.stop="toggleDark"><i class="fas fa-adjust"></i> {{ $t('global.switch', { attribute: pageConfigs.isDark ? $t('config.ui.light') : $t('config.ui.dark')}) }}</a>
                </base-dropdown>
            </div>
        </div>


        <div v-if="!duplicateTab" :class="['video-list', {'has-no-video': !hasVideos}, {'agenda-comments-visible': pageConfigs.showAgenda || pageConfigs.showComments}]" ref="videoListEle">


            <div v-if="pageConfigs.showAgenda || pageConfigs.showComments" class="video-item agenda-comments">
                <div class="agenda-wrapper" v-if="pageConfigs.showAgenda">

                    <div class="meeting-agenda-container">
                        <vue-scroll ref="vue-scroll-agenda" id="vue-scroll-agenda">
                            <template v-if="entity">
                                <h4 class="meeting-title" v-once>{{ entity.title }}</h4>

                                <view-paragraph class="mt-3" :label="$t('meeting.props.agenda')" :value="entity.agenda" />

                                <view-paragraph v-if="entity.description" class="mt-3" :label="$t('meeting.props.description')" :value="entity.description" html />

                                <view-uploads v-if="entity.attachments" :class="['mt-3', {'dark': pageConfigs.isDark}]" :label="$t('upload.attachments')" :name-label="$t('upload.attachment')" :value="entity.attachments" download-button-classes="text-gray" :url-prefix="`/meetings/${uuid}/downloads`" />
                            </template>
                        </vue-scroll>
                    </div>
                </div>

                <comments class="comments-wrapper" v-else-if="entity.config && entity.config.enableComments && pageConfigs.showComments" :is-dark="pageConfigs.isDark" :is-loading="isLoading" :user="user" :meeting="entity" :members="membersLive" :channel="this.channel" />
            </div>


            <template v-if="hasVideos">
                <div v-for="(item, itemIndex) in videoList" :key="`${item.uuid}${item.id}`" :class="['video-item', {'maximized': item.maximized}, {'local': item.local}, {'screen': item.screen}, {'fullscreen-item': item.id === fullScreenItemId}, {'audio-muted': item.audioMuted}, {'video-muted': item.videoMuted}, {'no-stream': !item.status}]" @dblclick="changeFocus(item)">
                    
                    <div class="video-wrapper">
                        <video autoplay playsinline ref="videos" :muted="item.muted" :id="item.id" :poster="item.status  ? null : '/images/video/no-stream.jpg'" :class="[{'no-poster': item.status && !item.videoMuted}]"></video>
                    </div>

                    <div class="caption">
                        <h6 v-if="item.status">
                            <span class="text-xs mr-1 text-success"><i class="fas fa-circle"></i></span>

                            <template v-if="item.local">
                                {{ item.screen ? $t('meeting.your_screen') : $t('meeting.you') }}
                            </template>

                            <template v-else>
                                {{ item.screen ? `${item.name}${$t('meeting.screen')}` : item.name }}
                            </template>
                        </h6>
                        <h6 v-else>
                            <span class="text-xs mr-1 text-danger"><i class="fas fa-circle"></i></span>

                            {{ item.local ? (item.localScreen ? $t('meeting.your_screen') : $t('meeting.you')) : item.name }}

                            <span class="bracketed text-danger">{{ $t('meeting.left') }}</span>
                        </h6>

                        <base-dropdown v-if="!item.maximized" tag="div" class="video-item-actions" direction="up" menu-classes="animated faster menuFadeInUpSmall" position="right" design="gray-darker">
                            <base-button slot="title" type="button" design="dark-primary" size="sm" data-toggle="dropdown" role="button"><i class="fas fa-ellipsis-v"></i></base-button>

                            <a v-if="!item.maximized" class="dropdown-item" @click="changeFocus(item)">Focus this!</a>
                        </base-dropdown>
                    </div>

                    <div v-if="!item.local" class="custom-controls-wrapper">
                        <div class="custom-controls">
                            <div class="status-icon" v-if="item.audioMuted && !item.videoMuted">
                                <i class="fas fa-microphone-slash disabled-text"></i>
                            </div>
                            <button @click="toggleRemoteAudio(item, itemIndex)">
                                <i :class="['fas', {'fa-volume-up enabled-text': !item.muted}, {'fa-volume-off disabled-text': item.muted}]"></i>
                            </button>
                            <button @click="toggleFullScreen(item, itemIndex)">
                                <i :class="['fas', {'fa-expand': !fullScreenInOn}, {'fa-compress': fullScreenInOn}]"></i>
                            </button>
                        </div>
                    </div>
                </div>
            </template>


            <div v-else class="video-item maximized countdown justify-content-center">
                <template v-if="entity">

                    <template v-if="entity.status === 'scheduled'">

                        <flip-countdown v-if="startDateTimeIsFuture" :deadline="entity.startDateTime" />

                        <template v-else>
                            <template v-if="entity.canModerate">
                                <h5 class="text-muted text-center my-3">
                                    {{ $t('meeting.waiting_for_you_to_start') }}
                                </h5>

                                <div class="d-flex justify-content-center my-3">
                                    <base-button type="button" design="primary" size="lg" @click="getOnline">{{ $t('global.click_to', { attribute: $t('meeting.get_live') }) }}</base-button>
                                </div>
                            </template>

                            <h5 v-else class="text-muted text-center my-3">
                                {{ $t('meeting.starting_any_time_now') }}
                            </h5>
                        </template>

                        <div class="text-center my-3">
                            <span class="text-muted">{{ $t('meeting.scheduled_for') }}</span><span class="text-light m-l-5" v-b-tooltip.hover.d500 :title="[entity.startDateTime, vars.serverDateTimeFormat] | moment(vars.defaultDateTimeFormat)">{{ [entity.startDateTime, vars.serverDateTimeFormat] | moment('calendar', null, { sameElse: vars.defaultDateTimeFormat }) }}</span>
                        </div>

                        <div v-if="liveMembersCount > 0" class="text-muted text-center my-3">
                            <span class="text-xs text-success mr-1"><i class="fas fa-circle"></i></span>
                            <animated-number :number="liveMembersCount" :delay="100" />
                            <span v-if="liveMembersCount>1">{{ $t('meeting.members_online') }}</span>
                            <span v-else>{{ $t('meeting.member_online') }}</span>
                        </div>

                        <template v-if="entity.canModerate">
                            <div class="d-flex justify-content-center my-3">
                                <base-button type="button" design="gray-darker" size="sm" @click="cancelMeeting">
                                    <i class="fas fa-times m-r-5"></i> {{ $t('meeting.cancel') }}</base-button>

                                <base-dropdown tag="div" size="sm">
                                    <base-button slot="title" type="button" design="gray-darker" size="sm" data-toggle="dropdown" role="button">
                                        <i class="far fa-clock m-r-5"></i>
                                        <span class="nav-link-inner--text">{{ $t('meeting.snooze') }}</span>
                                        <i class="fas fa-chevron-down m-l-5"></i>
                                    </base-button>

                                    <template>
                                        <button type="button" class="dropdown-item" v-for="opt in snoozeOpts" @click="snooze(opt.uuid)">{{ opt.name }} {{ $t(`list.general.durations.${opt.type}`) }}</button>
                                    </template>
                                </base-dropdown>
                            </div>
                        </template>

                    </template>


                    <template v-else-if="entity.status === 'live'">
                        <template v-if="roomIdAlive">
                            <h5 class="text-muted text-center my-3">
                                {{ $t('meeting.is_live_now') }}
                            </h5>

                            <div class="d-flex justify-content-center my-3">
                                <base-button type="button" design="primary" size="lg" @click="getOnline">{{ $t('global.click_to', { attribute: $t('meeting.get_live') }) }}</base-button>
                            </div>
                        </template>

                        <template v-else>
                            <template v-if="entity.canModerate">
                                <h5 class="text-muted text-center my-3">
                                    {{ $t('meeting.waiting_for_you_to_start') }}
                                </h5>

                                <div class="d-flex justify-content-center my-3">
                                    <base-button type="button" design="primary" size="lg" @click="getOnline">{{ $t('global.click_to', { attribute: $t('meeting.get_live') }) }}</base-button>
                                </div>
                            </template>

                            <h5 v-else class="text-muted text-center my-3">
                                {{ $t('meeting.starting_any_time_now') }}
                            </h5>
                        </template>

                        <div v-if="liveMembersCount > 0" class="text-muted text-center my-3">
                            <span class="text-xs text-success mr-1"><i class="fas fa-circle"></i></span>
                            <animated-number :number="liveMembersCount" :delay="100" />
                            <span v-if="liveMembersCount>1">{{ $t('meeting.members_online') }}</span>
                            <span v-else>{{ $t('meeting.member_online') }}</span>
                        </div>
                    </template>


                    <template v-else-if="entity.status === 'cancelled'">
                        <h4 class="text-muted text-center my-3">
                            {{ $t('meeting.meeting_cancelled') }}
                        </h4>
                    </template>

                    <template v-else-if="entity.status === 'ended'">
                        <h4 class="text-muted text-center my-3">
                            {{ $t('meeting.meeting_ended') }}
                        </h4>
                    </template>

                </template>
            </div>


        </div>

        <div v-else class="duplicate-tab d-flex justify-content-center align-items-center min-height-90vh">
            <h2>{{ $t('meeting.duplicate_tab') }}</h2>
        </div>
    </base-container>
</template>

<script>
    import FlipCountdown from 'vue2-flip-countdown'
    import io from 'socket.io-client'
    import RTCMultiConnection from 'rtcmulticonnection'
    import 'adapterjs'

    import { mapGetters, mapActions } from 'vuex'
    import '@js/echo-setup'
    import { initMedia, showMediaPermissionError, playIncomingMessage, playScreenshot } from '@core/utils/media'
    import AnimatedNumber from '@core/components/AnimatedNumber'
    import AppLogo from '@components/AppLogo'
    import Swal from '@core/configs/sweet-alert'
    import Comments from './partials/comments'
    import '@core/plugins/detect-duplicate-tab'

    window.io = io

    export default {
        components: {
            FlipCountdown,
            Comments,
            AnimatedNumber,
            RTCMultiConnection,
            AppLogo,
        },
        data() {
            return {
                uuid: null,
                entity: null,
                channel: null,
                prevRoute: null,
                fullScreenItemId: null,
                meetingRoomId: null,
                initUrl: 'meetings',
                fallBackRoute: 'appMeetingList',
                pageConfigs: {
                    isDark: true,
                    showAgenda: true,
                    showComments: false,
                    enableAudio: true,
                    enableVideo: true,
                    autoplay: true,
                },
                isLoading: false,
                newComments: false,
                roomIdAlive: false,
                showFlipClock: true,
                duplicateTab: false,
                fullScreenInOn: false,
                membersLive: [],
                videoList: [],
                socketURL: 'https://socket.scriptmint.com:9001/',
                rtcmConnection: null,
                localVideo: null,
                localScreenStreamid: null,
                countdownInterval: null,
                getOnlineTimer: null,
                snoozeOpts: [
                    { uuid: 5, name: 5, type: 'm' },
                    { uuid: 10, name: 10, type: 'm' },
                    { uuid: 15, name: 15, type: 'm' },
                    { uuid: 30, name: 30, type: 'm' },
                    { uuid: 60, name: 1, type: 'h' },
                ],
            }
        },
        computed: {
            ...mapGetters('config', [
                'vars',
                'configs',
            ]),
            ...mapGetters('user', {
                'userUuid': 'uuid'
            }),
            ...mapGetters('user', [
                'profile',
                'username',
                'hasPermission',
            ]),
            user() {
                return {
                    uuid: this.userUuid,
                    username: this.username,
                    name: this.profile.name,
                }
            },
            hasVideos() {
                return this.videoList && this.videoList.length
            },
            liveMembersCount() {
                return this.membersLive.length - 1
            },
            startDateTimeIsFuture() {
                const isInFuture = this.entity && this.showFlipClock && this.isStartDateTimeInFuture()
                if (isInFuture) {
                    this.startCountDown()
                } else {
                    if (this.countdownInterval) {
                        clearInterval(this.countdownInterval)
                    }
                }
                return isInFuture
            },
        },
        watch: {
            liveMembersCount(newVal, oldVal) {
                if (!window.isMeetingLiveCleared && newVal !== oldVal) {
                    this.meetingRoomCreated(this.entity)
                }
            },
        },
        methods: {
            ...mapActions('config', [
                'SetUiConfig',
            ]),
            ...mapActions('common', [
                'Init',
                'Get',
                'Custom',
                'GetPreRequisite',
            ]),
            toggleVideo() {
                let found = this.$refs.videos.find(video => {
                    return video.id === this.localVideo.id
                })
                const videoIndex = this.videoList.findIndex(video => {
                    return video.id === this.localVideo.id
                })

                if (found && found.srcObject) {
                    const stream = found.srcObject
                    const tracks = stream.getVideoTracks()
                    tracks.forEach(track => {
                        if(this.pageConfigs.enableVideo) {
                            this.pageConfigs.enableVideo = false
                            track.enabled = false
                            this.videoList[videoIndex].videoMuted = true
                            this.rtcmConnection.socket.emit('remoteMutedUnmuted', { 
                                    videoEnabled: false,
                                    streamid: stream.streamid
                                })
                        } else {
                            this.pageConfigs.enableVideo = true
                            track.enabled = true
                            this.videoList[videoIndex].videoMuted = false
                            this.rtcmConnection.socket.emit('remoteMutedUnmuted', { 
                                    videoEnabled: true,
                                    streamid: stream.streamid
                                })
                        }
                    })

                    this.rtcmConnection.extra.videoMuted = !this.pageConfigs.enableVideo
                    this.rtcmConnection.updateExtraData()
                } else {
                    this.localVideo = null
                }
            },
            toggleAudio() {
                let found = this.$refs.videos.find(video => {
                    return video.id === this.localVideo.id
                })
                const videoIndex = this.videoList.findIndex(video => {
                    return video.id === this.localVideo.id
                })

                if (found && found.srcObject) {
                    const stream = found.srcObject
                    const tracks = stream.getAudioTracks()
                    tracks.forEach(track => {
                        if(this.pageConfigs.enableAudio) {
                            this.pageConfigs.enableAudio = false
                            track.enabled = false
                            this.videoList[videoIndex].audioMuted = true
                            this.rtcmConnection.socket.emit('remoteMutedUnmuted', { 
                                    audioEnabled: false, 
                                    streamid: stream.streamid 
                                })
                        } else {
                            this.pageConfigs.enableAudio = true
                            track.enabled = true
                            this.videoList[videoIndex].audioMuted = true
                            this.rtcmConnection.socket.emit('remoteMutedUnmuted', {
                                    audioEnabled: true,
                                    streamid: stream.streamid
                                })
                        }
                    })

                    this.rtcmConnection.extra.audioMuted = !this.pageConfigs.enableAudio
                    this.rtcmConnection.updateExtraData()
                } else {
                    this.localVideo = null
                }
            },
            toggleRemoteAudio(videoItem, itemIndex) {
                if(videoItem.muted) {
                    this.videoList[itemIndex].muted = false
                    this.$refs.videos[itemIndex].muted = false
                } else {
                    this.videoList[itemIndex].muted = true
                    this.$refs.videos[itemIndex].muted = true
                }

                // if(videoItem.streamUserId) {
                //     const streamByUserId = this.rtcmConnection.streamEvents.selectFirst({ userid: videoItem.streamUserId }).stream;

                //     if(videoItem.muted) {
                //         streamByUserId.unmute('audio')
                //     } else {
                //         streamByUserId.mute('audio')
                //     }
                // }
            },
            toggleFullScreen(videoItem, itemIndex) {
                const targetParentEl = this.$refs['videoListEle']
                this.fullScreenItemId = videoItem.id
                this.$fullscreen.toggle(targetParentEl, {
                    wrap: false,
                    callback: (fullscreen) => {
                        this.fullScreenInOn = fullscreen
                    }
                })
            },
            isStartDateTimeInFuture() {
                return this.entity && this.entity.startDateTime && moment(this.entity.startDateTime, this.vars.serverDateTimeFormat)
                    .isAfter(moment())
            },
            startCountDown() {
                if (this.countdownInterval) {
                    clearInterval(this.countdownInterval)
                }

                this.countdownInterval = window.setInterval(() => {
                    if (this.isStartDateTimeInFuture()) {
                        this.showFlipClock = true
                    } else {
                        this.showFlipClock = false
                    }
                }, 1000)
            },
            changeFocus(item) {
                this.videoList.forEach(v => {
                    v.maximized = v.id === item.id
                })
            },
            toggleComments() {
                this.newComments = false
                this.pageConfigs.showComments = !this.pageConfigs.showComments
                if (!this.pageConfigs.showComments && !this.hasVideos) {
                    this.pageConfigs.showAgenda = true
                } else {
                    this.pageConfigs.showAgenda = false
                }
            },
            toggleAgenda() {
                this.pageConfigs.showAgenda = !this.pageConfigs.showAgenda
                if (!this.pageConfigs.showAgenda && !this.hasVideos) {
                    this.pageConfigs.showComments = true
                } else {
                    this.pageConfigs.showComments = false
                }
            },
            toggleDark() {
                this.pageConfigs.isDark = !this.pageConfigs.isDark
            },
            afterJoiningChannel(members) {
                this.membersLive = members
            },
            newMemberJoining(member) {
                this.membersLive.push(member)
            },
            memberLeaving(member) {
                this.membersLive = this.membersLive.filter(u => (u.uuid !== member.uuid))
            },
            meetingRoomCreated(e) {
                this.entity.roomId = e.roomId
                this.initMediaAndRtcmConnection()
                this.rtcmConnection.checkPresence(this.entity.roomId, (isRoomExist, roomid) => {
                    this.roomIdAlive = !!isRoomExist
                })
            },
            streamRemoved(e) {
                this.rtcmConnection.removeStream(e.id)
                this.rtcmOnStreamEnded(e)
            },
            meetingEnded(e) {
                this.closeConnectionAndStream()
                this.getInitialData()
            },
            meetingStatusChanged(e) {
                if (e.uuid === this.entity.uuid) {
                    if (this.entity.status === e.status) {
                        return
                    }

                    this.entity.status = e.status
                    this.entity.startDateTime = e.startDateTime
                    let meetingStatus = e.status

                    if (meetingStatus === 'scheduled' && e.delayed) {
                        meetingStatus = 'delayed'
                    }

                    const statusUpdateMessages = {
                        'live': 'meeting.is_live_now',
                        'delayed': 'meeting.meeting_delayed',
                        'cancelled': 'meeting.meeting_cancelled',
                        'ended': 'meeting.meeting_ended',
                    }

                    this.$toasted.success(this.$t(statusUpdateMessages[meetingStatus]), this.$toastConfig)
                }
            },
            gotNewComment() {
                if(!this.pageConfigs.showComments || this.fullScreenInOn) {
                    this.newComments = true
                    playIncomingMessage()
                }
            },
            joinChannel() {
                this.channel = window.Echo.join(`Meeting.${this.uuid}`)
                this.channel.here(this.afterJoiningChannel)
                    .joining(this.newMemberJoining)
                    .leaving(this.memberLeaving)
                    .listen('MeetingStatusChanged', this.meetingStatusChanged)
                    .listen('NewComment', this.gotNewComment)
                    .listenForWhisper('MeetingRoomCreated', this.meetingRoomCreated)
                    .listenForWhisper('RemovedStream', this.streamRemoved)
                    .listenForWhisper('MeetingEnded', this.meetingEnded)
            },
            async getInitialData() {
                this.isLoading = true
                try {
                    let response = await this.Get({ uuid: this.uuid })
                    this.entity = response
                    initMedia()

                    if (response.roomId && response.status === 'live') {
                        setTimeout(() => {
                            this.initMediaAndRtcmConnection()
                            this.rtcmConnection.checkPresence(response.roomId, (isRoomExist, roomid) => {
                                this.roomIdAlive = !!isRoomExist
                            })
                        }, 1000)
                    }

                    this.joinChannel()

                    this.isLoading = false
                    return response
                } catch (error) {
                    this.isLoading = false
                    formUtil.handleErrors(error)
                    this.$router.push({ name: this.fallBackRoute })
                }
            },
            doInit() {
                this.Init({ url: this.initUrl })

                if (window.isDuplicate()) {
                    this.duplicateTab = true
                }

                this.getInitialData()
            },
            logEvent(msg, args, type = 'log') {
                if(this.rtcmConnection.enableLogs) {
                    if(type === 'log') {
                        console.log(msg, args)
                    } else if(type === 'error') {
                        console.error(msg, args)
                    } else if(type === 'debug') {
                        console.debug(msg, args)
                    }
                }
            },
            rtcmOnStream(stream) {
                this.logEvent('On Stream: ', stream)
                let found = this.videoList.find(video => {
                    return video.id === stream.streamid
                })

                let streamInstance = stream.stream.idInstance ? JSON.parse(stream.stream.idInstance) : stream.stream
                if (streamInstance.isScreen && stream.type === 'local') {
                    this.localScreenStreamid = stream.streamid

                    let tracks = stream.stream.getTracks()
                    tracks.forEach(track => {
                        track.addEventListener('ended', this.stopSharingScreen)
                    })
                }

                if(this.videoList.length > 1) {
                    this.recheckLiveParticipants(null)
                }

                if (found === undefined) {
                    let video = {
                        id: stream.streamid,
                        streamUserId: stream.userid,
                        muted: stream.type === 'local',
                        ...stream.extra,
                        maximized: stream.type === 'local' && !streamInstance.isScreen,
                        local: stream.type === 'local',
                        screen: this.localScreenStreamid === stream.streamid,
                        status: true,
                    }

                    // let foundUserIndex = this.videoList.findIndex(item => item.uuid === stream.extra.uuid)

                    // if (foundUserIndex >= 0) {
                    //     const foundUserVideo = this.videoList[foundUserIndex]
                    //     if (!foundUserVideo.status) {
                    //         let newList = this.videoList.map(item => item.uuid !== foundUserVideo.uuid)
                    //         this.videoList = newList
                    //     }
                    // }

                    this.videoList.push(video)

                    if (stream.type === 'local' && this.localScreenStreamid !== stream.streamid) {
                        this.localVideo = video
                    }
                }

                this.autoSetVideoMaximized()

                setTimeout(() => {
                    for (let i = 0, len = this.$refs.videos.length; i < len; i++) {
                        if (this.$refs.videos[i].id === stream.streamid) {
                            this.$refs.videos[i].srcObject = stream.stream
                            break
                        }
                    }

                    // this.rtcmConnection.streamEvents.selectAll({
                    //     isScreen: true
                    // }).forEach(function(screenEvent) {
                    //     this.videoList.forEach((item, index) => {
                    //         if (item.id !== screenEvent.stream.streamid) {
                    //             this.videoList[index].screen = true
                    //         } else {
                    //             this.videoList[index].screen = false
                    //         }
                    //     })
                    // })
                }, 500)

                this.isLoading = false
            },
            recheckLiveParticipants: _.debounce(function(stream) {
                let newList = []
                let membersWhoLeft = []
                const liveParticipants = this.rtcmConnection.getAllParticipants()

                this.videoList.forEach((item, index) => {
                    const userIndex = liveParticipants.findIndex(m => m === item.streamUserId)
                    if ((!stream || (stream && item.id !== stream.streamid)) && (item.local || (!item.local && userIndex !== -1))) {
                        newList.push(item)
                    } else {
                        item.status = false
                        newList.push(item)
                    }
                })

                this.videoList = newList

                setTimeout(() => {
                    this.videoList = this.videoList.filter(v => v.status)
                    this.autoSetVideoMaximized()
                }, 3000)
            }, 1000),
            autoSetVideoMaximized() {
                if(this.videoList.length > 1) {
                    const maximizedRemoteVideoIndex = this.videoList.findIndex(v => !v.local && v.maximized && v.status)
                    if(maximizedRemoteVideoIndex === -1) {
                        const remoteVideoIndex = this.videoList.findIndex(v => !v.local)
                        if(remoteVideoIndex !== -1) {
                            this.videoList = this.videoList.map((v, index) => {
                                v.maximized = false
                                if(index === remoteVideoIndex) {
                                    v.maximized = true
                                }
                                return v
                            })
                        }
                    }
                } else if(this.videoList.length) {
                    this.videoList[0].maximized = true
                }
            },
            rtcmOnStreamEnded(stream) {
                this.recheckLiveParticipants(stream)
                this.autoSetVideoMaximized()
            },
            rtcmOnMediaError(error) {
                this.isLoading = false
                if(this.getOnlineTimer) {
                    clearTimeout(this.getOnlineTimer)
                }
                const msg = showMediaPermissionError(error)
                this.meetingAction('leave', { error: { name: error.name, title: msg.title } }, { alert: false })
            },
            initMediaAndRtcmConnection() {
                if(this.rtcmConnection) {
                    return 
                }

                this.rtcmConnection = new RTCMultiConnection()
                this.rtcmConnection.socketURL = this.socketURL
                this.rtcmConnection.autoCreateMediaElement = false
                // this.rtcmConnection.autoCloseEntireSession = true // set this line to close room as soon as room creator leaves
                this.rtcmConnection.enableLogs = true
                this.rtcmConnection.session = {
                    audio: true,
                    video: true,
                    // oneway: true,
                    // screen: true,
                }

                this.rtcmConnection.sdpConstraints.mandatory = {
                    OfferToReceiveAudio: true,
                    OfferToReceiveVideo: true
                }

                // STAR_FIX_VIDEO_AUTO_PAUSE_ISSUES
                // via: https://github.com/muaz-khan/RTCMultiConnection/issues/778#issuecomment-524853468
                var bitrates = 512;
                var resolutions = 'Ultra-HD';
                var videoConstraints = {};

                if (resolutions == 'HD') {
                    videoConstraints = {
                        width: {
                            ideal: 1280
                        },
                        height: {
                            ideal: 720
                        },
                        frameRate: 30
                    };
                }

                if (resolutions == 'Ultra-HD') {
                    videoConstraints = {
                        width: {
                            ideal: 1920
                        },
                        height: {
                            ideal: 1080
                        },
                        frameRate: 30
                    };
                }

                this.rtcmConnection.mediaConstraints = {
                    video: videoConstraints,
                    audio: true
                };

                var CodecsHandler = this.rtcmConnection.CodecsHandler;

                this.rtcmConnection.processSdp = function(sdp) {
                    var codecs = 'vp8';

                    if (codecs.length) {
                        sdp = CodecsHandler.preferCodec(sdp, codecs.toLowerCase());
                    }

                    if (resolutions == 'HD') {
                        sdp = CodecsHandler.setApplicationSpecificBandwidth(sdp, {
                            audio: 128,
                            video: bitrates,
                            screen: bitrates
                        });

                        sdp = CodecsHandler.setVideoBitrates(sdp, {
                            min: bitrates * 8 * 1024,
                            max: bitrates * 8 * 1024,
                        });
                    }

                    if (resolutions == 'Ultra-HD') {
                        sdp = CodecsHandler.setApplicationSpecificBandwidth(sdp, {
                            audio: 128,
                            video: bitrates,
                            screen: bitrates
                        });

                        sdp = CodecsHandler.setVideoBitrates(sdp, {
                            min: bitrates * 8 * 1024,
                            max: bitrates * 8 * 1024,
                        });
                    }

                    return sdp;
                };
                // END_FIX_VIDEO_AUTO_PAUSE_ISSUES

                this.rtcmConnection.iceServers = []
                this.rtcmConnection.iceServers.push({
                    urls: 'stun:st.kodemint.in:5349'
                })
                this.rtcmConnection.iceServers.push({
                    urls: 'turn:st.kodemint.in:5349',
                    credential: 'guest',
                    username: 'password'
                })

                // this.rtcmConnection.onNewParticipant = (participantId, userPreferences) => {
                //     debugger
                // }

                this.rtcmConnection.onstream = this.rtcmOnStream
                this.rtcmConnection.onstreamended = this.rtcmOnStreamEnded
                this.rtcmConnection.onmute = this.rtcmOnMute
                this.rtcmConnection.onunmute = this.rtcmOnUnmute
                this.rtcmConnection.onMediaError = this.rtcmOnMediaError
                this.rtcmConnection.onUserIdAlreadyTaken = this.onUserIdAlreadyTaken

                this.rtcmConnection.setCustomSocketEvent('remoteMutedUnmuted')
            },
            onUserIdAlreadyTaken(useridAlreadyTaken, yourNewUserId) {
                this.rtcmConnection.userid = yourNewUserId
            },
            rtcmOnMute(stream) {
                const videoIndex = this.videoList.findIndex(v => v.id === stream.streamid)
                const videoEle = this.$refs.videos.find(video => {
                    return video.id === stream.streamid
                })

                if(stream.muteType === 'video') {
                    this.videoList[videoIndex].videoMuted = true
                } else if(stream.muteType === 'audio') {
                    this.videoList[videoIndex].muted = true
                } else {
                    this.videoList[videoIndex].videoMuted = true
                    this.videoList[videoIndex].muted = true
                    videoEle.srcObject = null
                }
            },
            rtcmOnUnmute(stream) {
                const videoIndex = this.videoList.findIndex(v => v.id === stream.streamid)
                const videoEle = this.$refs.videos.find(video => {
                    return video.id === stream.streamid
                })

                if(stream.unmuteType === 'video') {
                    this.videoList[videoIndex].videoMuted = false
                } else if(stream.unmuteType === 'audio') {
                    this.videoList[videoIndex].muted = false
                } else {
                    this.videoList[videoIndex].videoMuted = false
                    this.videoList[videoIndex].muted = false
                    videoEle.srcObject = stream
                }
            },
            rtcmOnRemoteMuteUnmute(data) {
                const videoIndex = this.videoList.findIndex(video => {
                    return video.id === data.streamid
                })

                const stream = this.rtcmConnection.streamEvents[data.streamid].stream

                if(data.hasOwnProperty('audioEnabled')) {
                    if(data.audioEnabled) {
                        this.videoList[videoIndex].audioMuted = false
                    } else {
                        this.videoList[videoIndex].audioMuted = true
                    }
                } else if(data.hasOwnProperty('videoEnabled')) {
                    // const videoEle = this.$refs.videos.find(video => {
                    //     return video.id === data.streamid
                    // })

                    if(data.videoEnabled) {
                        this.videoList[videoIndex].videoMuted = false
                    } else {
                        this.videoList[videoIndex].videoMuted = true
                    }  
                }
            },
            beforeUnload(event) {
                if(this.localVideo) {
                    this.channel.whisper('RemovedStream', this.localVideo)
                }
            },
            openRoom(meetingRoomId) {
                this.rtcmConnection.open(meetingRoomId, (isRoomOpened, roomid, error) => {
                    this.rtcmConnection.socket.on('remoteMutedUnmuted', this.rtcmOnRemoteMuteUnmute)
                    this.logEvent('Room Opened: ', roomid)
                    this.isLoading = false
                    if (error) {
                        formUtil.handleErrors(error)
                    } else if (isRoomOpened === true) {
                        if(this.getOnlineTimer) {
                            clearTimeout(this.getOnlineTimer)
                        }
                        this.channel.whisper('MeetingRoomCreated', {
                            roomId: meetingRoomId
                        })
                        this.$toasted.success(this.$t('meeting.meeting_created'), this.$toastConfig)
                    }
                })
            },
            joinRoom(meetingRoomId) {
                this.rtcmConnection.join(meetingRoomId, (isJoined, roomid, error) => {
                    this.rtcmConnection.socket.on('remoteMutedUnmuted', this.rtcmOnRemoteMuteUnmute)
                    this.logEvent('Room Joined: ', roomid)
                    this.isLoading = false
                    if (isJoined === false || error) {
                        formUtil.handleErrors(error)
                    } else {
                        if(this.getOnlineTimer) {
                            clearTimeout(this.getOnlineTimer)
                        }
                        this.$toasted.success(this.$t('meeting.meeting_joined'), this.$toastConfig)
                    }
                })
            },
            meetingAction(action, data = {}, opts = { alert: 'confirm' }) {
                const defaultOpts = { alert: 'confirm' }
                opts = Object.assign({}, defaultOpts, opts)

                const callApi = (dataToSend) => {
                    this.isLoading = true
                    data = dataToSend ? dataToSend : data

                    this.Custom({
                            url: `/${this.initUrl}/${this.uuid}/${action}`,
                            method: 'post',
                            data
                        })
                        .then(response => {
                            this.entity = response.meeting
                            this.$toasted.success(response.message, this.$toastConfig)
                            if (opts.callback) {
                                opts.callback(response)
                            }
                            this.isLoading = false
                        })
                        .catch(error => {
                            this.isLoading = false
                            formUtil.handleErrors(error)
                        })
                }

                if (!action) {
                    this.isLoading = false
                    return
                }

                if (opts.alert === 'confirm' || opts.alert === true) {
                    formUtil.confirmAction()
                        .then((result) => {
                            if (result.value) {
                                callApi()
                            } else {
                                this.isLoading = false
                                result.dismiss === Swal.DismissReason.cancel
                            }
                        })
                } else if (opts.alert === 'input') {
                    swtAlert.fire({
                            title: opts.title,
                            input: 'text',
                            inputPlaceholder: opts.inputPlaceholder,
                            showCancelButton: true,
                            confirmButtonText: 'Proceed!',
                            cancelButtonText: 'Go Back!'
                        })
                        .then((result) => {
                            if (result.value) {
                                let toSend = {}
                                toSend[opts.fieldName] = result.value
                                callApi(toSend)
                            } else {
                                this.isLoading = false
                                result.dismiss === Swal.DismissReason.cancel
                            }
                        })
                } else {
                    callApi()
                }
            },
            snooze(period) {
                this.meetingAction('snooze', { period })
            },
            leaveMeeting() {
                this.meetingAction('leave')
            },
            endMeeting() {
                this.isLoading = true
                this.meetingAction('end', null, {
                    callback: (e) => {
                        this.closeConnectionAndStream()
                        this.channel.whisper('MeetingEnded', { status: e.meeting.status })
                    }
                })
            },
            cancelMeeting() {
                this.meetingAction('cancel', null, { alert: 'input', title: $t('meeting.reason_for_cancellation'), inputPlaceholder: $t('meeting.reason_for_cancellation'), fieldName: 'cancellationReason' })
            },
            startGetOnlineTimer() {
                if(this.getOnlineTimer) {
                    clearTimeout(this.getOnlineTimer)
                }
                if(this.videoList.length) {
                    return
                }
                const alertContent = {
                    title: $t('misc.refresh_confirm.title'),
                    text: $t('misc.refresh_confirm.text'),
                    showCancelButton: true,
                    confirmButtonText: $t('misc.refresh_confirm.confirm_btn'),
                    cancelButtonText: $t('misc.refresh_confirm.cancel_btn')
                }
                this.getOnlineTimer = setTimeout(() => {
                    swtAlert.fire(alertContent)
                        .then((result) => {
                            if (result.value) {
                                window.location.reload()
                            } else {
                                this.startGetOnlineTimer()
                            }
                        })
                }, 10000)
            },
            getOnline() {
                this.isLoading = true
                const meetingStatusEalier = this.entity.status

                this.startGetOnlineTimer()

                this.initMediaAndRtcmConnection()

                this.Custom({
                        url: `/${this.initUrl}/${this.uuid}/join`,
                        method: 'post',
                    })
                    .then(response => {
                        this.meetingRoomId = response.meeting.roomId
                        this.entity = response.meeting
                        this.rtcmConnection.extra = {
                            username: this.user.username,
                            name: this.user.name,
                            uuid: this.user.uuid,
                            image: this.profile.image,
                            audioMuted: !this.pageConfigs.enableAudio,
                            videoMuted: !this.pageConfigs.enableVideo,
                        }

                        this.rtcmConnection.checkPresence(this.meetingRoomId, (isRoomExist, roomid) => {
                            if (isRoomExist === true) {
                                this.joinRoom(this.meetingRoomId)
                            } else {
                                if (this.entity.canModerate) {
                                    this.openRoom(this.meetingRoomId)
                                } else {
                                    this.isLoading = false
                                    if(this.getOnlineTimer) {
                                        clearTimeout(this.getOnlineTimer)
                                    }
                                    this.$toasted.error(this.$t('meeting.room_not_found'), this.$toastConfig.error)
                                }
                            }
                        })
                    })
                    .catch(error => {
                        this.isLoading = false
                        clearTimeout(this.getOnlineTimer)
                        formUtil.handleErrors(error)
                    })
            },
            closeConnectionAndStream() {
                if (this.rtcmConnection) {
                    this.rtcmConnection.getAllParticipants()
                        .forEach((pid) => {
                            this.rtcmConnection.disconnectWith(pid)
                        })

                    this.rtcmConnection.attachStreams.forEach((localStream) => {
                        localStream.stop()
                    })

                    this.rtcmConnection.closeSocket()
                    this.rtcmConnection = null
                }
                this.videoList = []
            },
            getOffline() {
                this.isLoading = true
                this.meetingAction('leave', null, {
                    alert: 'confirm',
                    callback: (e) => {
                        this.closeConnectionAndStream()
                    }
                })
            },
            shareScreen() {
                this.isLoading = true

                this.rtcmConnection.addStream({
                    screen: true,
                })
            },
            stopSharingScreen() {
                this.isLoading = true

                let found = this.$refs.videos.find(video => {
                    return video.id === this.localScreenStreamid
                })

                if (found && found.srcObject) {
                    let tracks = found.srcObject.getTracks()
                    tracks.forEach(track => {
                        track.removeEventListener('ended', this.stopSharingScreen)
                        track.stop()
                    })
                    this.rtcmConnection.removeStream(this.localScreenStreamid)
                    this.localScreenStreamid = null
                    this.isLoading = false
                } else {
                    this.localScreenStreamid = null
                    this.isLoading = false
                }
            }
        },
        mounted() {
            if (this.$route.params.uuid) {
                this.uuid = this.$route.params.uuid
            }
            this.doInit()
            window.addEventListener('beforeunload', this.beforeUnload)
        },
        created() {
            this.SetUiConfig({ pageHeaderShow: false, pageFooterShow: false })

            // detect 2G
            if (navigator.connection &&
                navigator.connection.type === 'cellular' &&
                navigator.connection.downlinkMax <= 0.115) {
                alert('2G is not supported. Please use a better internet service.');
            }
        },
        beforeDestroy() {
            if(!window.isMeetingLiveCleared) {
                this.isLoading = true
                if (this.countdownInterval) {
                    clearInterval(this.countdownInterval)
                }

                this.SetUiConfig({ pageHeaderShow: true, pageFooterShow: true })

                if(window.Echo) {
                    if (this.channel) {
                        this.channel.stopListening('MeetingStatusChanged')
                        this.channel.stopListening('NewComment')
                    }
                    window.Echo.leave(`Meeting.${this.uuid}`)
                }

                this.closeConnectionAndStream()
                window.removeEventListener('beforeunload', this.beforeUnload)

                if(this.entity && this.entity.status === 'live') {
                    this.Custom({
                            url: `/${this.initUrl}/${this.uuid}/leave`,
                            method: 'post',
                        })
                }

                window.isMeetingLiveCleared = true
            }
        },
        beforeRouteEnter(to, from, next) {
            if (!to.params.uuid) {
                next({ name: from === 'appMeetingView' ? from : 'AppMeetingList' })
            } else {
                next(vm => {
                    vm.prevRoute = from
                })
            }
        },
        beforeRouteLeave(to, from, next) {
            this.isLoading = true
            if (this.countdownInterval) {
                clearInterval(this.countdownInterval)
            }

            this.SetUiConfig({ pageHeaderShow: true, pageFooterShow: true })

            if(window.Echo) {
                if (this.channel) {
                    this.channel.stopListening('MeetingStatusChanged')
                    this.channel.stopListening('NewComment')
                }
                window.Echo.leave(`Meeting.${this.uuid}`)
            }

            this.closeConnectionAndStream()
            window.removeEventListener('beforeunload', this.beforeUnload)

            if(this.entity && this.entity.status === 'live') {
                this.Custom({
                        url: `/${this.initUrl}/${this.uuid}/leave`,
                        method: 'post',
                    })
                    .then(response => {
                        window.isMeetingLiveCleared = true
                        next()
                    })
                    .catch(error => {
                        window.isMeetingLiveCleared = true
                        next()
                    })
            } else {
                window.isMeetingLiveCleared = true
                next()
            }
        },
    }

</script>

<style lang="scss">
    @import '~@js/core/assets/scss/imports.scss';

    .meeting-page.dark {
        background: darken($gray-darkest, 5);
    }

</style>
