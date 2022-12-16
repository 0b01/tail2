import { h } from 'preact';
import React from 'preact/compat'

interface Props {
  xLabelHeight: number
  isXLabelReverse: boolean
  children: any
}

export default function YLabelAligner({
  xLabelHeight,
  isXLabelReverse,
  children
}: Props) {
  const style = {
    [isXLabelReverse ? 'marginBottom' : 'marginTop']: `${xLabelHeight}px`
  }
  return <div style={style}>{children}</div>
}
