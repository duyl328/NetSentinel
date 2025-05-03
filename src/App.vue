<script setup lang="ts">
import { useRoute, useRouter } from 'vue-router'
import PathUtils from '@/utils/pathUtils'
import StringUtils from '@/utils/stringUtils'
import type { subRoute, subRouteList } from '@/types/devIndex'
import app from '@/constants/app'
import { ref } from 'vue'

const router = useRouter()
// 是否展示生成路由
const isShowGenerateRouter = ref(false)

// region 获取路由列表
// 自动获取路由列表
const routes = {
  ...import.meta.glob('@/views/*.vue'),
  ...import.meta.glob('@/views/dev/*.vue'),
}
const route = useRoute()

// 子路由列表
const subRouteLists: subRouteList = []
// 遍历路由page列表进行路由渲染
Object.keys(routes).map((path) => {
  if ('.vue' === PathUtils.extname(path).trim()) {
    const fileName = PathUtils.basename(path).split('.')[0]
    const s = StringUtils.toCustomCase(fileName).toLowerCase().split('-')[0]
    const items = {
      displayName: fileName,
      path: `/${s}`, // 生成路径
    }
    subRouteLists.push(items)
  }
  return ''
})

/**
 * 列表路径是否激活
 * @param path
 */
const isActive = (path: string) => {
  return route.path.includes(path)
}

/**
 * 列表点击调准
 */
function listClickJump(item: subRoute) {
  console.log(item.path)
  router.push({ path: item.path })
}

// endregion

// region 开发和生产状态确认
const nodeEnv: string = import.meta.env.MODE

console.log(nodeEnv)
if (nodeEnv !== undefined && !StringUtils.isBlank(nodeEnv) && nodeEnv === app.DEVELOPMENT) {
  app.IS_PRODUCTION = false
  isShowGenerateRouter.value = app.IS_SHOW_GENERATE_ROUTER
}

// endregion
</script>

<template>
  <div class="main-container">
    <!-- 顶部导航 -->
    <ul class="top-navigation" v-if="isShowGenerateRouter">
      <li v-for="(subRoute, index) in subRouteLists" :key="index">
        <v-btn :type="isActive(subRoute.path) ? 'primary' : ''" @click="listClickJump(subRoute)">
          {{ subRoute.displayName }}
        </v-btn>
      </li>
    </ul>

    <hr v-if="isShowGenerateRouter" />

    <!--  展示主要内容-->
    <div class="main-show">
      <router-view />
    </div>
  </div>
</template>

<style scoped lang="scss">
.main-container {
  position: relative;

  .top-navigation {
    z-index: 10;
    position: absolute;
    background: red;
    display: flex;
    justify-content: space-between; /* 或 space-around / space-evenly */
    list-style: none;
    padding: 0;
    margin: 0;

    li {
      flex: 1;
      margin: 5px;
      text-align: center; /* 可选：让文本居中 */
    }
  }

  .main-show {
    width: 100%;
    height: 100%;
  }
}
</style>
