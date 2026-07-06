import { Modal, Button } from '@arco-design/web-react'

interface Props {
  visible: boolean
  title: string
  confirmText: string
  confirmType?: 'primary' | 'danger'
  children: React.ReactNode
  onConfirm: () => void
  onCancel: () => void
}

export default function TwoStepConfirmModal({ visible, title, confirmText, confirmType = 'danger', children, onConfirm, onCancel }: Props) {
  return (
    <Modal
      title={title}
      visible={visible}
      onOk={onConfirm}
      onCancel={onCancel}
      footer={
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 12 }}>
          <Button onClick={onCancel}>取消</Button>
          <Button type={confirmType} onClick={onConfirm}>{confirmText}</Button>
        </div>
      }
    >
    </Modal>
  )
}
