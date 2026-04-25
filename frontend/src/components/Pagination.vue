<template>
  <div v-if="total > 0" class="pg-bar">
    <el-button size="small" :disabled="current <= 1" @click="go(1)">首页</el-button>
    <el-button size="small" :disabled="current <= 1" @click="go(current - 1)">上一页</el-button>
    <span class="pg-info">第 <b>{{ current }}</b> / <b>{{ totalPages }}</b> 页，共 <b>{{ total }}</b> 条</span>
    <el-button size="small" :disabled="current >= totalPages" @click="go(current + 1)">下一页</el-button>
    <el-button size="small" :disabled="current >= totalPages" @click="go(totalPages)">末页</el-button>
    <span class="pg-jump">
      跳转第
      <el-input v-model.number="jumpVal" size="small" style="width:58px;margin:0 4px" @keyup.enter="doJump" />
      页
      <el-button size="small" @click="doJump">GO</el-button>
    </span>
  </div>
</template>

<script setup>
import { ref, computed, watch } from 'vue'

const props = defineProps({
  total: { type: Number, default: 0 },
  pageSize: { type: Number, default: 30 },
  current: { type: Number, default: 1 }
})
const emit = defineEmits(['update:current'])

const totalPages = computed(() => Math.max(1, Math.ceil(props.total / props.pageSize)))
const jumpVal = ref(props.current)

watch(() => props.current, v => { jumpVal.value = v })

function go(p) {
  const clamped = Math.max(1, Math.min(p, totalPages.value))
  emit('update:current', clamped)
  jumpVal.value = clamped
}

function doJump() {
  const p = parseInt(jumpVal.value)
  if (!isNaN(p)) go(p)
}
</script>

<style scoped>
.pg-bar {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 14px 4px 4px;
  flex-wrap: wrap;
}
.pg-info {
  font-size: 13px;
  color: #606266;
  margin: 0 6px;
}
.pg-jump {
  display: flex;
  align-items: center;
  gap: 4px;
  font-size: 13px;
  color: #606266;
  margin-left: 10px;
}
</style>
