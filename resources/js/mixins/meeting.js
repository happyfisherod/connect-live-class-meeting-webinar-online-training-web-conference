import { mapGetters, mapActions } from 'vuex'

import AnimatedNumber from '@core/components/AnimatedNumber'
import io from 'socket.io-client'
import RTCMultiConnection from 'rtcmulticonnection'
import 'adapterjs'

import { setupPusher } from '@js/echo-setup'
import { initMedia, showMediaPermissionError, playIncomingMessage, playScreenshot } from '@core/utils/media'
import '@core/plugins/detect-duplicate-tab'
import Swal from '@core/configs/sweet-alert'

import AppLogo from '@components/AppLogo'

window.io = io

export default {
    components: {
        AnimatedNumber,
        RTCMultiConnection,
        AppLogo,
    },
    data() {
        return {
            uuid: null,
            entity: null,
            isLoading: false,
            prevRoute: null,
            channel: null,
            countdownInterval: null,
            getOnlineTimer: null,

            fullScreenItemId: null,
            meetingRoomId: null,
            initUrl: 'meetings',
            fallBackRoute: 'appMeetingList',
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
            videoConstraints: {},
            pageConfigs: {
                isDark: true,
                showAgenda: true,
                showComments: false,
                enableAudio: true,
                enableVideo: true,
                autoplay: true,
                showEnableAudioBtn: true,
                showEnableVideoBtn: true,
                showShareScreenBtn: true,
            },
            meetingRulesHost: {
                session: {
                    audio: false,
                    video: false,
                    screen: false,
                    oneway: false,
                },
                mediaConstraints: {
                    audio: false,
                    video: false,
                    screen: false,
                },
                mandatory: {
                    OfferToReceiveAudio: false,
                    OfferToReceiveVideo: false,
                },
            },
            meetingRulesGuest: {
                session: {
                    audio: false,
                    video: false,
                    screen: false,
                    oneway: false,
                },
                mediaConstraints: {
                    audio: false,
                    video: false,
                    screen: false,
                },
                mandatory: {
                    OfferToReceiveAudio: false,
                    OfferToReceiveVideo: false,
                },
            },
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
            'uiConfigs',
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
            return this.videoList && this.videoList.length > 0 ? this.videoList.length : 0
        },
        hasVideosClasses() {
            if (!this.hasVideos) {
                return 'has-no-video'
            }

            return 'has-videos ' + (this.hasVideos > 3 ? 'has-gt-3-videos' : (this.hasVideos > 1 ? 'has-2-3-videos' : 'has-1-video'))
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
            if (!window.isLiveMeetingDestroyed && newVal !== oldVal) {
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

        // query / countdown / timer methods
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
                    if (this.showFlipClock && !document.hasFocus()) {
                        playIncomingMessage()
                    }
                    this.showFlipClock = false
                }
            }, 1000)
        },
        startGetOnlineTimer() {
            if (this.getOnlineTimer) {
                clearTimeout(this.getOnlineTimer)
            }
            if (this.videoList.length) {
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
            }, 15000)
        },

        // toggle methods
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
                    if (this.pageConfigs.enableAudio) {
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
                    if (this.pageConfigs.enableVideo) {
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
        toggleRemoteAudio(videoItem, itemIndex) {
            if (videoItem.muted) {
                this.videoList[itemIndex].muted = false
                this.$refs.videos[itemIndex].muted = false
            } else {
                this.videoList[itemIndex].muted = true
                this.$refs.videos[itemIndex].muted = true
            }

            // if(videoItem.streamUserId) {
            //     const streamByUserId = this.rtcmConnection.streamEvents.selectFirst({ userid: videoItem.streamUserId }).stream

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
        toggleComments() {
            this.newComments = false
            this.pageConfigs.showAgenda = false
            this.pageConfigs.showComments = !this.pageConfigs.showComments
        },
        toggleAgenda() {
            this.pageConfigs.showComments = false
            this.pageConfigs.showAgenda = !this.pageConfigs.showAgenda
        },
        changeFocus(item) {
            this.videoList.forEach(v => {
                v.maximized = v.id === item.id
            })
        },

        // event callback methods
        beforeUnload(event) {
            if (this.localVideo) {
                this.channel.whisper('RemovedStream', this.localVideo)
            }
        },

        // channel event callback methods
        afterJoiningChannel(members) {
            this.membersLive = members
        },
        newMemberJoining(member) {
            this.membersLive.push(member)
        },
        memberLeaving(member) {
            this.membersLive = this.membersLive.filter(u => (u.uuid !== member.uuid))
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
            if (!this.pageConfigs.showComments || this.fullScreenInOn) {
                this.newComments = true
                playIncomingMessage()
            }
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

        // channel action methods
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

        // rtcm event callback methods
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

            if (this.videoList.length > 1) {
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
                    hasAudio: streamInstance.isAudio || streamInstance.audio,
                    hasVideo: streamInstance.isVideo || streamInstance.video || streamInstance.isScreen || streamInstance.screen,
                }

                if (streamInstance.isScreen) {
                    video.videoMuted = false
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
        rtcmOnStreamEnded(stream) {
            this.recheckLiveParticipants(stream)
            this.autoSetVideoMaximized()
        },
        rtcmOnMediaError(error) {
            this.isLoading = false
            if (this.getOnlineTimer) {
                clearTimeout(this.getOnlineTimer)
            }
            const msg = showMediaPermissionError(error)
            this.meetingAction('leave', { error: { name: error.name, title: msg.title } }, { alert: false })
        },
        rtcmOnMute(stream) {
            const videoIndex = this.videoList.findIndex(v => v.id === stream.streamid)
            const videoEle = this.$refs.videos.find(video => {
                return video.id === stream.streamid
            })

            if (stream.muteType === 'video') {
                this.videoList[videoIndex].videoMuted = true
            } else if (stream.muteType === 'audio') {
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

            if (stream.unmuteType === 'video') {
                this.videoList[videoIndex].videoMuted = false
            } else if (stream.unmuteType === 'audio') {
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

            if (data.hasOwnProperty('audioEnabled')) {
                if (data.audioEnabled) {
                    this.videoList[videoIndex].audioMuted = false
                } else {
                    this.videoList[videoIndex].audioMuted = true
                }
            } else if (data.hasOwnProperty('videoEnabled')) {
                // const videoEle = this.$refs.videos.find(video => {
                //     return video.id === data.streamid
                // })

                if (data.videoEnabled) {
                    this.videoList[videoIndex].videoMuted = false
                } else {
                    this.videoList[videoIndex].videoMuted = true
                }
            }
        },
        rtcmOnUserIdAlreadyTaken(useridAlreadyTaken, yourNewUserId) {
            this.rtcmConnection.userid = yourNewUserId
        },

        // rtc action methods
        initMediaAndRtcmConnection() {
            if (!this.rtcmConnection) {
                this.rtcmConnection = new RTCMultiConnection()
                this.rtcmConnection.socketURL = this.socketURL
                this.rtcmConnection.autoCreateMediaElement = false
                // this.rtcmConnection.autoCloseEntireSession = true // set this line to close room as soon as room creator leaves
                this.rtcmConnection.enableLogs = true

                // STAR_FIX_VIDEO_AUTO_PAUSE_ISSUES
                // via: https://github.com/muaz-khan/RTCMultiConnection/issues/778#issuecomment-524853468
                var bitrates = 512
                var resolutions = 'Ultra-HD'
                var videoConstraints = {}

                if (resolutions == 'HD') {
                    this.videoConstraints = {
                        width: {
                            ideal: 1280
                        },
                        height: {
                            ideal: 720
                        },
                        frameRate: 30
                    }
                }

                if (resolutions == 'Ultra-HD') {
                    this.videoConstraints = {
                        width: {
                            ideal: 1920
                        },
                        height: {
                            ideal: 1080
                        },
                        frameRate: 30
                    }
                }
                
                var CodecsHandler = this.rtcmConnection.CodecsHandler

                this.rtcmConnection.processSdp = function(sdp) {
                    var codecs = 'vp8'

                    if (codecs.length) {
                        sdp = CodecsHandler.preferCodec(sdp, codecs.toLowerCase())
                    }

                    if (resolutions == 'HD') {
                        sdp = CodecsHandler.setApplicationSpecificBandwidth(sdp, {
                            audio: 128,
                            video: bitrates,
                            screen: bitrates
                        })

                        sdp = CodecsHandler.setVideoBitrates(sdp, {
                            min: bitrates * 8 * 1024,
                            max: bitrates * 8 * 1024,
                        })
                    }

                    if (resolutions == 'Ultra-HD') {
                        sdp = CodecsHandler.setApplicationSpecificBandwidth(sdp, {
                            audio: 128,
                            video: bitrates,
                            screen: bitrates
                        })

                        sdp = CodecsHandler.setVideoBitrates(sdp, {
                            min: bitrates * 8 * 1024,
                            max: bitrates * 8 * 1024,
                        })
                    }

                    return sdp
                }
                // END_FIX_VIDEO_AUTO_PAUSE_ISSUES

                // this.rtcmConnection.candidates = {
                //     turn: true,
                //     stun: false,
                //     host: false
                // }

                this.rtcmConnection.onstream = this.rtcmOnStream
                this.rtcmConnection.onstreamended = this.rtcmOnStreamEnded
                this.rtcmConnection.onmute = this.rtcmOnMute
                this.rtcmConnection.onunmute = this.rtcmOnUnmute
                this.rtcmConnection.onMediaError = this.rtcmOnMediaError
                this.rtcmConnection.onUserIdAlreadyTaken = this.rtcmOnUserIdAlreadyTaken

                this.rtcmConnection.setCustomSocketEvent('remoteMutedUnmuted')
            }
            
            this.rtcmConnection.iceServers = [...this.configs.iceServers]

            this.rtcmConnection.session = {
                ...this.meetingRulesHost.session
            }

            this.rtcmConnection.sdpConstraints.mandatory = {
                ...this.meetingRulesHost.mandatory
            }

            this.rtcmConnection.mediaConstraints = {
                video: this.meetingRulesHost.mediaConstraints.video ? this.videoConstraints : false,
                audio: this.meetingRulesHost.mediaConstraints.audio,
                screen: this.meetingRulesHost.mediaConstraints.screen,
            }

        },
        closeConnectionAndStream() {
            if (this.rtcmConnection) {
                if (this.localVideo) {
                    this.rtcmConnection.removeStream(this.localVideo.id)
                    this.channel.whisper('RemovedStream', this.localVideo)
                }

                this.rtcmConnection.attachStreams.forEach((localStream) => {
                    localStream.stop()
                })

                this.rtcmConnection.getAllParticipants()
                    .forEach((pid) => {
                        this.rtcmConnection.disconnectWith(pid)
                    })

                this.rtcmConnection.leave()
                this.rtcmConnection.closeSocket()
                this.localVideo = null
                this.localScreenStreamid = null
                this.rtcmConnection = null
            }
            this.videoList = []
        },
        recheckLiveParticipants(stream) {
            let newList = []
            let membersWhoLeft = []
            const liveParticipants = this.rtcmConnection ? this.rtcmConnection.getAllParticipants() : []

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
        },
        autoSetVideoMaximized() {
            if (this.videoList.length > 1) {
                const maximizedRemoteVideoIndex = this.videoList.findIndex(v => !v.local && v.maximized && v.status)
                if (maximizedRemoteVideoIndex === -1) {
                    const remoteVideoIndex = this.videoList.findIndex(v => !v.local)
                    if (remoteVideoIndex !== -1) {
                        this.videoList = this.videoList.map((v, index) => {
                            v.maximized = false
                            if (index === remoteVideoIndex) {
                                v.maximized = true
                            }
                            return v
                        })
                    }
                }
            } else if (this.videoList.length) {
                this.videoList[0].maximized = true
            }
        },
        openRoom(meetingRoomId) {
            this.rtcmConnection.session = {
                ...this.meetingRulesHost.session
            }

            this.rtcmConnection.mediaConstraints = {
                ...this.meetingRulesHost.mediaConstraints
            }

            this.rtcmConnection.sdpConstraints.mandatory = {
                ...this.meetingRulesHost.mandatory
            }

            this.rtcmConnection.open(meetingRoomId, (isRoomOpened, roomid, error) => {
                this.rtcmConnection.socket.on('remoteMutedUnmuted', this.rtcmOnRemoteMuteUnmute)
                this.logEvent('Room Opened: ', roomid)
                this.isLoading = false

                if (error) {
                    formUtil.handleErrors(error)
                } else if (isRoomOpened === true) {

                    if (this.getOnlineTimer) {
                        clearTimeout(this.getOnlineTimer)
                    }

                    this.updatePageConfigs(true)

                    this.channel.whisper('MeetingRoomCreated', {
                        roomId: meetingRoomId
                    })
                    this.$toasted.success(this.$t('meeting.meeting_created'), this.$toastConfig)
                }
            })
        },
        joinRoom(meetingRoomId) {
            this.rtcmConnection.session = {
                ...this.meetingRulesGuest.session
            }

            this.rtcmConnection.mediaConstraints = {
                ...this.meetingRulesGuest.mediaConstraints
            }

            this.rtcmConnection.sdpConstraints.mandatory = {
                ...this.meetingRulesGuest.mandatory
            }

            this.rtcmConnection.join(meetingRoomId, (isJoined, roomid, error) => {
                this.rtcmConnection.socket.on('remoteMutedUnmuted', this.rtcmOnRemoteMuteUnmute)
                this.logEvent('Room Joined: ', roomid)
                this.isLoading = false

                if (isJoined === false || error) {
                    formUtil.handleErrors(error)
                } else {
                    if (this.getOnlineTimer) {
                        clearTimeout(this.getOnlineTimer)
                    }

                    this.updatePageConfigs()

                    this.$toasted.success(this.$t('meeting.meeting_joined'), this.$toastConfig)
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
                    track.enabled = false
                    track.stop()
                })
                this.rtcmConnection.removeStream(this.localScreenStreamid)
                this.channel.whisper('RemovedStream', found.srcObject)

                // this.videoList = this.videoList.filter(video => video.id !== this.localScreenStreamid)
                this.localScreenStreamid = null
                this.isLoading = false
            } else {
                this.localScreenStreamid = null
                this.isLoading = false
            }
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
                                if (this.getOnlineTimer) {
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
        getOffline() {
            this.isLoading = true
            this.meetingAction('leave', null, {
                alert: 'confirm',
                callback: (e) => {
                    this.closeConnectionAndStream()
                }
            })
        },

        // meeting action methods
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
        cancelMeeting() {
            this.meetingAction('cancel', null, { alert: 'input', title: $t('meeting.reason_for_cancellation'), inputPlaceholder: $t('meeting.reason_for_cancellation'), fieldName: 'cancellationReason' })
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

        // page methods
        updatePageConfigs(isInitiator = false) {
            let configOptions = {}

            if (this.entity.type.uuid === 'video_conference') {
                configOptions = {
                    enableAudio: true,
                    enableVideo: true,
                    showEnableAudioBtn: true,
                    showEnableVideoBtn: true,
                    showShareScreenBtn: true,
                }
            } else if (this.entity.type.uuid === 'audio_conference') {
                configOptions = {
                    enableAudio: true,
                    enableVideo: true,
                    showEnableAudioBtn: true,
                    showEnableVideoBtn: false,
                    showShareScreenBtn: true,
                }
            } else if (this.entity.type.uuid === 'webinar') {
                configOptions = isInitiator ? {
                    enableAudio: true,
                    enableVideo: true,
                    showEnableAudioBtn: true,
                    showEnableVideoBtn: true,
                    showShareScreenBtn: true,
                } : {
                    enableAudio: true,
                    enableVideo: true,
                    showEnableAudioBtn: false,
                    showEnableVideoBtn: false,
                    showShareScreenBtn: false,
                }
            } else if (this.entity.type.uuid === 'live_class') {
                configOptions = isInitiator ? {
                    enableAudio: true,
                    enableVideo: true,
                    showEnableAudioBtn: true,
                    showEnableVideoBtn: true,
                    showShareScreenBtn: true,
                } : {
                    enableAudio: true,
                    enableVideo: true,
                    showEnableAudioBtn: true,
                    showEnableVideoBtn: false,
                    showShareScreenBtn: false,
                }
            } else if (this.entity.type.uuid === 'podcast') {
                configOptions = isInitiator ? {
                    enableAudio: true,
                    enableVideo: false,
                    showEnableAudioBtn: true,
                    showEnableVideoBtn: false,
                    showShareScreenBtn: false,
                } : {
                    enableAudio: true,
                    enableVideo: false,
                    showEnableAudioBtn: false,
                    showEnableVideoBtn: false,
                    showShareScreenBtn: false,
                }
            }

            configOptions.objForEach((value, key) => this.pageConfigs[key] = value)

            this.rtcmConnection.extra.audioMuted = !this.pageConfigs.enableAudio
            this.rtcmConnection.extra.videoMuted = !this.pageConfigs.enableVideo
            this.rtcmConnection.updateExtraData()
        },
        updateMeetingRules() {
            if (this.entity.type.uuid === 'video_conference') {
                this.meetingRulesHost = {
                    session: {
                        audio: true,
                        video: true,
                        screen: false,
                        oneway: false,
                    },
                    mediaConstraints: {
                        audio: true,
                        video: this.videoConstraints,
                        screen: false,
                    },
                    mandatory: {
                        OfferToReceiveAudio: true,
                        OfferToReceiveVideo: true,
                    },
                }
                this.meetingRulesGuest = {
                    session: {
                        audio: true,
                        video: true,
                        screen: false,
                        oneway: false,
                    },
                    mediaConstraints: {
                        audio: true,
                        video: this.videoConstraints,
                        screen: false,
                    },
                    mandatory: {
                        OfferToReceiveAudio: true,
                        OfferToReceiveVideo: true,
                    },
                }
            } else if (this.entity.type.uuid === 'audio_conference') {
                this.meetingRulesHost = {
                    session: {
                        audio: true,
                        video: false,
                        screen: false,
                        oneway: false,
                    },
                    mediaConstraints: {
                        audio: true,
                        video: false,
                        screen: false,
                    },
                    mandatory: {
                        OfferToReceiveAudio: true,
                        OfferToReceiveVideo: true,
                    },
                }
                this.meetingRulesGuest = {
                    session: {
                        audio: true,
                        video: false,
                        screen: false,
                        oneway: false,
                    },
                    mediaConstraints: {
                        audio: true,
                        video: false,
                        screen: false,
                    },
                    mandatory: {
                        OfferToReceiveAudio: true,
                        OfferToReceiveVideo: true,
                    },
                }
            } else if (this.entity.type.uuid === 'webinar') {
                this.meetingRulesHost = {
                    session: {
                        audio: true,
                        video: true,
                        screen: false,
                        oneway: true,
                    },
                    mediaConstraints: {
                        audio: true,
                        video: this.videoConstraints,
                        screen: false,
                    },
                    mandatory: {
                        OfferToReceiveAudio: false,
                        OfferToReceiveVideo: false,
                    },
                }
                this.meetingRulesGuest = {
                    session: {
                        audio: true,
                        video: true,
                        screen: false,
                        oneway: true,
                    },
                    mediaConstraints: {
                        audio: true,
                        video: false,
                        screen: false,
                    },
                    mandatory: {
                        OfferToReceiveAudio: true,
                        OfferToReceiveVideo: true,
                    },
                }
            } else if (this.entity.type.uuid === 'live_class') {
                this.meetingRulesHost = {
                    session: {
                        audio: true,
                        video: true,
                        screen: false,
                        oneway: false,
                    },
                    mediaConstraints: {
                        audio: true,
                        video: this.videoConstraints,
                        screen: false,
                    },
                    mandatory: {
                        OfferToReceiveAudio: true,
                        OfferToReceiveVideo: false,
                    },
                }
                this.meetingRulesGuest = {
                    session: {
                        audio: true,
                        video: false,
                        screen: false,
                        oneway: false,
                    },
                    mediaConstraints: {
                        audio: true,
                        video: false,
                        screen: false,
                    },
                    mandatory: {
                        OfferToReceiveAudio: true,
                        OfferToReceiveVideo: true,
                    },
                }
            } else if (this.entity.type.uuid === 'podcast') {
                this.meetingRulesHost = {
                    session: {
                        audio: true,
                        video: false,
                        screen: false,
                        oneway: true,
                    },
                    mediaConstraints: {
                        audio: true,
                        video: false,
                        screen: false,
                    },
                    mandatory: {
                        OfferToReceiveAudio: false,
                        OfferToReceiveVideo: false,
                    },
                }
                this.meetingRulesGuest = {
                    session: {
                        audio: true,
                        video: false,
                        screen: false,
                        oneway: true,
                    },
                    mediaConstraints: {
                        audio: false,
                        video: false,
                        screen: false,
                    },
                    mandatory: {
                        OfferToReceiveAudio: true,
                        OfferToReceiveVideo: false,
                    },
                }
            }
        },
        getInitialData() {
            this.isLoading = true

            return this.Get({ uuid: this.uuid })
                .then(response => {
                    this.entity = response
                    this.updateMeetingRules()

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
                })
                .catch(error => {
                    this.isLoading = false
                    formUtil.handleErrors(error)
                    this.$router.push({ name: this.fallBackRoute })
                    return error
                })
        },
        logEvent(msg, args, type = 'log') {
            if (this.rtcmConnection.enableLogs) {
                if (type === 'log') {
                    console.log(msg, args)
                } else if (type === 'error') {
                    console.error(msg, args)
                } else if (type === 'debug') {
                    console.debug(msg, args)
                }
            }
        },
        destroyPage() {
            if (this.countdownInterval) {
                clearInterval(this.countdownInterval)
            }

            this.SetUiConfig({ pageHeaderShow: true, pageFooterShow: true })

            this.closeConnectionAndStream()

            if (window.Echo) {
                if (this.channel) {
                    this.channel.stopListening('MeetingStatusChanged')
                    this.channel.stopListening('NewComment')
                }
                window.Echo.leave(`Meeting.${this.uuid}`)
            }
        },
        doInit() {
            this.Init({ url: this.initUrl })

            if (window.isDuplicate()) {
                this.duplicateTab = true
            }

            this.getInitialData()
        },
    },
    mounted() {
        if (this.$route.params.uuid) {
            this.uuid = this.$route.params.uuid
        }

        if (!window.Echo) {
            setupPusher()
        }

        this.doInit()
        window.addEventListener('beforeunload', this.beforeUnload)
    },
    created() {
        this.SetUiConfig({ pageHeaderShow: false, pageFooterShow: false })

        // detect 2G and alert
        if (navigator.connection &&
            navigator.connection.type === 'cellular' &&
            navigator.connection.downlinkMax <= 0.115) {
            alert('2G is not supported. Please use a better internet service.')
        }
    },
    beforeDestroy() {
        if (!window.isPageDestroyed) {
            this.isLoading = true

            this.destroyPage()

            if (this.entity && this.entity.status === 'live') {
                this.Custom({
                    url: `/${this.initUrl}/${this.uuid}/leave`,
                    method: 'post',
                })
            }

            window.isPageDestroyed = true
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

        this.destroyPage()
        window.removeEventListener('beforeunload', this.beforeUnload)

        if (this.entity && this.entity.status === 'live') {
            this.Custom({
                    url: `/${this.initUrl}/${this.uuid}/leave`,
                    method: 'post',
                })
                .then(response => {
                    window.isPageDestroyed = true
                    next()
                })
                .catch(error => {
                    window.isPageDestroyed = true
                    next()
                })
        } else {
            window.isPageDestroyed = true
            next()
        }
    },
}
