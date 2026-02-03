-- =========================================================================
-- 1. 字段定义
-- =========================================================================
local f_resp_code = Field.new("http.response.code")
local f_full_uri = Field.new("http.request.full_uri")
local f_frame_num = Field.new("frame.number")
local f_time_epoch = Field.new("frame.time_epoch")
local f_reassembled = Field.new("tcp.reassembled.data")
local f_payload = Field.new("tcp.payload")
local f_file_data = Field.new("http.file_data")
local f_seg_count = Field.new("tcp.segment.count")
local f_retrans = Field.new("tcp.analysis.retransmission")
local f_request_in = Field.new("http.request_in")
-- [新增] 替换 Header 源的字段
local f_exported_pdu = Field.new("exported_pdu.exported_pdu")

-- =========================================================================
-- 2. 获取过滤器
-- =========================================================================
local user_filter = os.getenv("flowanalyzer_filter")
if not user_filter or user_filter == "" then
    user_filter = "http"
end

-- =========================================================================
-- 3. 初始化监听器
-- =========================================================================
local tap = Listener.new("frame", user_filter)

-- =========================================================================
-- 4. 辅助函数
-- =========================================================================

local function val_to_str(val)
    if val == nil then
        return ""
    end
    return tostring(val)
end

-- 查找 Header 结束位置
local function find_header_split_pos(hex_str)
    if not hex_str then
        return nil
    end

    -- 1. 找 0D0A0D0A (CRLF CRLF)
    local start_idx = 1
    while true do
        local s, e = string.find(hex_str, "0D0A0D0A", start_idx, true)
        if not s then
            break
        end
        if s % 2 == 1 then
            return s
        end -- 确保字节对齐
        start_idx = s + 1
    end

    -- 2. 找 0A0A (LF LF)
    start_idx = 1
    while true do
        local s, e = string.find(hex_str, "0A0A", start_idx, true)
        if not s then
            break
        end
        if s % 2 == 1 then
            return s
        end
        start_idx = s + 1
    end
    return nil
end

-- [核心性能优化] 智能提取 Header Hex
-- 即使 Body 不限制大小，Header 依然建议只扫描前 2KB，因为 Header 不会那么长
local function extract_header_smart(field_info)
    if not field_info then
        return ""
    end

    local range = field_info.range
    local total_len = range:len()

    -- 预览前 2KB
    local cap_len = 2048
    if total_len < cap_len then
        cap_len = total_len
    end

    -- [关键] 转为 Hex 并强制转为大写
    local preview_hex = string.upper(range(0, cap_len):bytes():tohex())

    -- 查找分隔符
    local pos = find_header_split_pos(preview_hex)

    if pos then
        return string.sub(preview_hex, 1, pos - 1)
    else
        return preview_hex
    end
end

-- 直接获取完整 Hex
local function get_full_hex(field_info)
    if not field_info then
        return ""
    end
    -- 强制转大写，保持格式一致
    return string.upper(field_info.range:bytes():tohex())
end

-- =========================================================================
-- 5. 主处理逻辑
-- =========================================================================
function tap.packet(pinfo, tvb)
    -- 过滤 TCP 重传
    if f_retrans() then
        return
    end

    local frame_num = f_frame_num()
    if not frame_num then
        return
    end

    -- === 1. 确定类型 (req/rep) 和 信息 (URI/Code) ===
    local col_type = "data"
    local col_uri_or_code = ""

    local code = f_resp_code()
    local uri = f_full_uri()

    if code then
        col_type = "rep"
        col_uri_or_code = tostring(code)
    elseif uri then
        col_type = "req"
        col_uri_or_code = tostring(uri)
    end

    -- === 2. 基础信息 ===
    local col_frame = tostring(frame_num)
    local col_time = val_to_str(f_time_epoch())

    -- === 3. Header Hex ===
    -- 逻辑：Exported PDU > TCP Reassembled > TCP Payload
    local col_header_hex = ""

    local exp_pdu = f_exported_pdu()

    if exp_pdu then
        col_header_hex = extract_header_smart(exp_pdu)
    else
        local seq_count = f_seg_count()
        local reass = nil
        if seq_count then
            reass = f_reassembled()
        end

        if reass then
            col_header_hex = extract_header_smart(reass)
        else
            local pay = f_payload()
            if pay then
                col_header_hex = extract_header_smart(pay)
            end
        end
    end

    -- === 4. File Data (Body Hex) ===
    -- [修改] 移除大小判断，无条件转换所有 Body
    local col_file_data = ""
    local fd = f_file_data()

    if fd then
        col_file_data = get_full_hex(fd)
    end

    -- === 5. Request In (仅响应包有) ===
    local col_req_in = ""
    local req_in = f_request_in()
    if req_in then
        col_req_in = tostring(req_in)
    end

    -- === 输出 (Tab 分隔) ===
    print(table.concat({col_type, -- 1. req / rep
    col_frame, -- 2. Frame Number
    col_time, -- 3. Time Epoch
    col_header_hex, -- 4. Header Bytes (Hex)
    col_file_data, -- 5. File Data (Hex) [完整数据，不跳过]
    col_uri_or_code, -- 6. URI / Code
    col_req_in -- 7. Request In
    }, "\t"))
end
