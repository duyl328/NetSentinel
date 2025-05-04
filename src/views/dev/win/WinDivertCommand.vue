<script setup lang="ts">
import CommandManager from '@/components/CommandManager.vue'
import type { CommandType } from '@/types/command'

const commands: CommandType[] = [
  {
    name: 'win_divert_command',
    description: '获取系统网络连接',
    params: [
      {
        name: 'name',
        label: 'name',
        type: 'text',
        value: 'XXX',
        placeholder: 'string'
      }
    ],
    result: null
  }
]
</script>

<template>
  <CommandManager :pro="commands"></CommandManager>
</template>

<style scoped></style>
