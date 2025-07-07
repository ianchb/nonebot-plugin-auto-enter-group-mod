import requests
from nonebot import logger, on_command, on_notice, on_request
from nonebot.adapters.onebot.v11 import Bot, GroupDecreaseNoticeEvent, GroupMessageEvent, GroupRequestEvent, Message
from nonebot.adapters.onebot.v11.permission import GROUP_ADMIN, GROUP_OWNER
from nonebot.params import CommandArg
from nonebot.permission import SUPERUSER
from nonebot.plugin import PluginMetadata

from .utils import (
    add_keyword_allowed,
    enable_exit_recording,
    load_data,
    record_exit,
    remove_keyword_allowed,
)

# 插件元数据
__plugin_meta__ = PluginMetadata(
    name="加群自动审批",
    description="帮助管理员审核入群请求，退群自动记录拒绝入群",
    type="application",
    homepage="https://github.com/padoru233/nonebot-plugin-auto-enter-group",
    usage="""
        查看关键词：群主/管理员可查看入群关键词
        添加/删除允许关键词 <关键词>：添加/删除自动允许入群关键词
        入群答案自动进行关键词模糊匹配
        启用/禁用退群黑名单：启用/禁用本群退群黑名单，启用后退群用户将无法再次加入
    """,
    supported_adapters={"~onebot.v11"},
)


# 加载数据
data = load_data()


# 读取关键词命令
get_keywords = on_command(
    "查看关键词",
    priority=5,
    permission=SUPERUSER | GROUP_ADMIN | GROUP_OWNER,
    block=False,
)


@get_keywords.handle()
async def handle_get_keywords(event: GroupMessageEvent):
    group_id = str(event.group_id)
    allowed_keywords = data["groups"].get(group_id, {}).get("allowed_keywords", [])
    message = ""
    if allowed_keywords:
        message += f"当前允许入群关键词：{', '.join(allowed_keywords)}\n"
    else:
        message += "当前没有允许入群关键词\n"
    await get_keywords.finish(message)


# 添加允许关键词命令
add_allowed_keyword = on_command(
    "添加允许关键词",
    priority=5,
    permission=SUPERUSER | GROUP_ADMIN | GROUP_OWNER,
    block=True,
)


@add_allowed_keyword.handle()
async def handle_add_allowed(event: GroupMessageEvent, args: Message = CommandArg()):
    group_id = str(event.group_id)
    keyword = args.extract_plain_text().strip().lower()
    if not keyword:
        await add_allowed_keyword.finish("关键词不能为空，请输入有效的关键词。")
        return
    if add_keyword_allowed(group_id, keyword):
        await add_allowed_keyword.finish(f"允许关键词 '{keyword}' 已添加到当前群组。")
    else:
        await add_allowed_keyword.finish(f"允许关键词 '{keyword}' 已存在于当前群组。")


# 删除允许关键词命令
remove_allowed_keyword = on_command(
    "删除允许关键词",
    priority=5,
    permission=SUPERUSER | GROUP_ADMIN | GROUP_OWNER,
    block=True,
)


@remove_allowed_keyword.handle()
async def handle_remove_allowed(event: GroupMessageEvent, args: Message = CommandArg()):
    group_id = str(event.group_id)
    keyword = args.extract_plain_text().strip().lower()
    if not keyword:
        await remove_allowed_keyword.finish("关键词不能为空，请输入有效的关键词。")
        return
    if remove_keyword_allowed(group_id, keyword):
        await remove_allowed_keyword.finish(f"允许关键词 '{keyword}' 已从当前群组删除。")
    else:
        await remove_allowed_keyword.finish(f"允许关键词 '{keyword}' 不存在于当前群组。")


# 启用退群记录命令
enable_exit_cmd = on_command(
    "启用退群黑名单",
    priority=5,
    permission=SUPERUSER | GROUP_ADMIN | GROUP_OWNER,
    block=True,
)


@enable_exit_cmd.handle()
async def handle_enable_exit(event: GroupMessageEvent):
    group_id = str(event.group_id)
    enable_exit_recording(group_id, True)
    await enable_exit_cmd.finish(f"群 {group_id} 的退群黑名单功能已启用。")
    logger.info(f"群 {group_id} 的退群黑名单功能已启用。")


# 禁用退群记录命令
disable_exit_cmd = on_command(
    "禁用退群黑名单",
    priority=5,
    permission=SUPERUSER | GROUP_ADMIN | GROUP_OWNER,
    block=True,
)


@disable_exit_cmd.handle()
async def handle_disable_exit(event: GroupMessageEvent):
    group_id = str(event.group_id)
    enable_exit_recording(group_id, False)
    await disable_exit_cmd.finish(f"群 {group_id} 的退群黑名单功能已禁用。")
    logger.info(f"群 {group_id} 的退群黑名单功能已禁用。")


# 处理群成员减少事件
group_decrease_handler = on_notice(priority=1, block=False)


@group_decrease_handler.handle()
async def handle_group_decrease(bot: Bot, event: GroupDecreaseNoticeEvent):
    # 检查事件类型
    if event.sub_type in ["leave", "kick"]:
        group_id = str(event.group_id)
        user_id = str(event.user_id)
        # 检查该群组是否启用了退群记录
        group_data = data["groups"].get(group_id, {})
        if group_data.get("exit_records", {}).get("enabled", False):
            record_exit(user_id, group_id)
            try:
                user_name = (await bot.get_stranger_info(user_id=int(user_id)))["nickname"] or "未知昵称"
            except Exception:
                user_name = "未知昵称"
            await group_decrease_handler.finish(f"群友「{user_name}」({user_id})离开了我们，再见，或许再也不见。")
        else:
            try:
                user_name = (await bot.get_stranger_info(user_id=int(user_id)))["nickname"] or "未知昵称"
            except Exception:
                user_name = "未知昵称"
            await group_decrease_handler.finish(f"群友「{user_name}」({user_id})离开了我们，祝她幸福。")


# 处理群请求事件
group_request_handler = on_request(priority=1, block=False)


async def verify_join_code_with_backend(join_code: str, qq_number: str) -> bool:
    try:
        response = requests.post(
            'YOUR_BACKEND_SERVER',
            json={
                'join_code': join_code,
                'qq_number': qq_number
            },
            timeout=10
        )

        if response.status_code == 200:
            data = response.json()
            return data.get('success', False)
        else:
            logger.warning(f"后端验证入群码失败，状态码: {response.status_code}")
            return False
    except Exception as e:
        logger.error(f"后端验证入群码时出错: {str(e)}")
        return False


def extract_join_code(comment: str) -> str:
    """从验证信息中提取入群码"""
    import re
    pattern = r'\b[A-Z0-9\-_]{8}\b'
    matches = re.findall(pattern, comment.upper())
    return matches[0] if matches else ""


@group_request_handler.handle()
async def handle_first_receive(bot: Bot, event: GroupRequestEvent):
    flag = event.flag
    sub_type = event.sub_type
    if sub_type == "invite":
        return
    group_id = str(event.group_id)
    user_id = str(event.user_id)
    comment = event.comment  # type: ignore
    original_comment = comment
    comment_lower = comment.lower()
    group_data = data["groups"].get(group_id, {})
    # 检查群组是否开启了退群记录功能
    if group_data.get("exit_records", {}).get("enabled", False):
        # 检查用户是否在退群记录中
        if user_id in group_data.get("exit_records", {}).get("members", []):
            await bot.set_group_add_request(
                flag=flag,
                sub_type=sub_type,
                approve=False,
                reason="直到现在还执迷于过去，真让人看不下去。",
            )
            logger.info(f"用户 {user_id} 被拒绝加入群 {group_id}，原因：已退出过该群。")
            return

    # 优先检查入群码验证
    join_code = extract_join_code(original_comment)
    if join_code:
        logger.info(f"检测到入群码: {join_code}，开始验证...")
        if await verify_join_code_with_backend(join_code, user_id):
            await bot.set_group_add_request(flag=flag, sub_type=sub_type, approve=True, reason=" ")
            logger.info(f"入群码验证成功，已批准用户 {user_id} 加入群 {group_id}")
            await group_request_handler.finish(f"入群码验证成功，欢迎 {user_id} 来到本群！")
        else:
            await bot.set_group_add_request(
                flag=flag,
                sub_type=sub_type,
                approve=False,
                reason="入群码验证失败，请重新获取有效的入群码。",
            )
            logger.info(f"入群码验证失败，已拒绝用户 {user_id} 加入群 {group_id}")

    # 如果没有入群码，则使用关键词匹配
    allowed_answers = group_data.get("allowed_keywords", [])

    if any(keyword in comment_lower for keyword in allowed_answers):
        await bot.set_group_add_request(flag=flag, sub_type=sub_type, approve=True, reason=" ")
        logger.info("请求基于关键词匹配已批准。")
        await group_request_handler.finish(f"关键词验证成功，欢迎 {user_id} 来到本群！")
    else:
        # 如果不含允许关键词且群组有配置关键词，则拒绝
        await bot.set_group_add_request(
            flag=flag,
            sub_type=sub_type,
            approve=False,
            reason="验证信息不符合要求，请提供正确的验证信息或入群码。",
        )
        logger.info(f"用户 {user_id} 被拒绝加入群 {group_id}，原因：验证信息不包含允许关键词且无有效入群码。")
