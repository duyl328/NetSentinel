<script setup lang="ts">
import CommandManager from '@/components/CommandManager.vue'
import type { CommandType } from '@/types/command'

const commands: CommandType[] = [
  {
    name: 'win_divert_command',
    description: '显示所有网络连接信息',
    params: [],
    result: null,
  },
  {
    name: 'monitor_network_with_windivert_command',
    description: '使用WinDivert监控网络数据包',
    params: [],
    result: null,
  },
]
</script>

<template>
  <CommandManager :pro="commands"></CommandManager>
</template>

<style scoped></style>
