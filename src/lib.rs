use anyhow::anyhow;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use kovi::{
    Message, MsgEvent, PluginBuilder as P, RuntimeBot,
    bot::message::Segment,
    chrono,
    event::AdminMsgEvent,
    log,
    serde_json::json,
    tokio::{self, fs::File, io::AsyncReadExt},
    utils::{load_json_data, save_json_data},
};
use parking_lot::RwLock;
use rand::Rng;
use std::{
    ops::Deref,
    path::{Path, PathBuf},
    sync::Arc,
};

static CMD: &str = ".diy";

#[derive(Debug, Clone, serde::Serialize)]
struct DiyMsg {
    cmd: String,
    #[serde(rename = "type")]
    type_: DiyMsgType,
    #[serde(skip)]
    regex_cache: Option<regex::Regex>,
    message: Message,
}

impl<'de> serde::Deserialize<'de> for DiyMsg {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Debug, serde::Deserialize)]
        struct TmpDiyMsg {
            cmd: String,
            #[serde(rename = "type")]
            type_: DiyMsgType,
            message: Message,
        }

        let tmp = TmpDiyMsg::deserialize(deserializer)?;

        let regex_cache = match tmp.type_ {
            DiyMsgType::Text => None,
            DiyMsgType::Regex => {
                let re = regex::Regex::new(&tmp.cmd);

                match re {
                    Ok(re) => Some(re),
                    Err(err) => {
                        log::error!("cmd `{}` parse error: {err}", tmp.cmd);
                        None
                    }
                }
            }
        };

        Ok(DiyMsg {
            cmd: tmp.cmd,
            type_: tmp.type_,
            regex_cache,
            message: tmp.message,
        })
    }
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
enum DiyMsgType {
    Text,
    Regex,
}

#[kovi::plugin]
async fn main() {
    let bot = P::get_runtime_bot();
    let data_path = bot.get_data_path();
    let data_path = Arc::new(data_path);

    let diy_map: Vec<DiyMsg> =
        load_json_data(Default::default(), data_path.as_path().join("msg.json")).unwrap();

    let diy_map: Arc<RwLock<Vec<DiyMsg>>> = Arc::new(RwLock::new(diy_map));

    // 回复diy_msg
    P::on_msg({
        let diy_map = diy_map.clone();
        move |e| on_msg(e, diy_map.clone())
    });

    // 控制diy-map
    P::on_admin_msg({
        let data_path = data_path.clone();
        let diy_map = diy_map.clone();
        move |e| on_admin_msg(e, bot.clone(), diy_map.clone(), data_path.clone())
    });

    P::drop({
        let data_path = data_path.clone();
        move || on_drop(data_path.clone(), diy_map.clone())
    });
}

async fn on_drop(data_path: Arc<PathBuf>, diy_map: Arc<RwLock<Vec<DiyMsg>>>) {
    if let Err(err) = save_json_data(diy_map.read().deref(), data_path.as_path().join("msg.json")) {
        log::error!("diy-map: Failed to save: {err}");
    }
}

async fn on_msg(e: Arc<MsgEvent>, diy_map: Arc<RwLock<Vec<DiyMsg>>>) -> anyhow::Result<()> {
    let text = match e.borrow_text() {
        Some(v) => v,
        None => return Ok(()),
    };

    let message = {
        let diy_map_lock = diy_map.read();

        // Try to find matching command
        let diy_msg = diy_map_lock
            .iter()
            .find(|msg| match msg.type_ {
                DiyMsgType::Text => msg.cmd == text,
                DiyMsgType::Regex => {
                    let Some(re) = &msg.regex_cache else {
                        return false;
                    };

                    re.is_match(text)
                }
            })
            .ok_or(anyhow!("No matching command found"))?;

        diy_msg.message.clone()
    };

    if !message.contains("image") {
        e.reply(message);
        return Ok(());
    }

    let seg_iter = message.into_iter();

    let mut new_msg = Message::default();
    for seg in seg_iter {
        if seg.type_ != "image" {
            new_msg.push(seg);
            continue;
        }

        let path = seg.data.get("file").unwrap().as_str().unwrap();
        let base64_img = match image_to_base64(path).await {
            Some(v) => v,
            None => {
                log::error!("diy-msg: Failed to convert image to base64");
                return Ok(());
            }
        };

        let new_img_seg = Segment::new(
            "image",
            json!({ "file": format!("base64://{}", base64_img) }),
        );

        new_msg.push(new_img_seg);
    }

    e.reply(new_msg);

    Ok(())
}

async fn on_admin_msg(
    e: Arc<AdminMsgEvent>,
    bot: Arc<RuntimeBot>,
    diy_map: Arc<RwLock<Vec<DiyMsg>>>,
    data_path: Arc<PathBuf>,
) {
    let (diy_msg, msg_type, regex_cache) = {
        let cmd_msg = match e.borrow_text() {
            Some(v) => v,
            None => return,
        };

        if !cmd_msg.starts_with(CMD) {
            return;
        }

        let cmd_msg = cmd_msg.trim_start_matches(CMD).trim();

        if cmd_msg.is_empty() {
            e.reply_and_quote("请输入需要构建的消息");
            return;
        }

        // Check for regex command prefix
        if cmd_msg.starts_with("regex ") {
            let regex_pattern = cmd_msg.trim_start_matches("regex ").trim();
            // Validate regex pattern
            let regex = match regex::Regex::new(regex_pattern) {
                Ok(regex) => regex,
                Err(err) => {
                    e.reply_and_quote(format!("正则表达式无效: {err}"));
                    return;
                }
            };
            (regex_pattern.to_string(), DiyMsgType::Regex, Some(regex))
        } else {
            (cmd_msg.to_string(), DiyMsgType::Text, None)
        }
    };

    let reply_msg_vec = e.message.get("reply");

    if reply_msg_vec.is_empty() {
        e.reply_and_quote("请引用需要构建的消息");
        return;
    }

    let id = reply_msg_vec[0]
        .data
        .get("id")
        .unwrap()
        .as_str()
        .unwrap()
        .parse::<i64>()
        .unwrap();

    let res = match bot.get_msg(id as i32).await {
        Ok(v) => v,
        Err(_) => {
            e.reply_and_quote("获取引用消息失败");
            return;
        }
    };

    let reply_msg = match res.data.get("message") {
        Some(v) => match Message::from_value(v.clone()) {
            Ok(v) => v,
            Err(v) => {
                log::error!("diy-msg: {v}");
                e.reply_and_quote("无法解析消息内容");
                return;
            }
        },
        None => {
            log::info!("diy-msg: 无法获取消息内容");
            return;
        }
    };

    let mut new_reply_msg = Message::default();

    for seg in reply_msg.into_iter() {
        match seg.type_.as_str() {
            "image" => {
                let url = seg.data.get("url").unwrap().as_str().unwrap();
                match download_img(url, data_path.as_path().join("img")).await {
                    Ok(v) => {
                        let seg = Segment::new("image", json!({ "file": v }));
                        new_reply_msg.push(seg);
                    }
                    Err(err) => {
                        log::error!("diy-msg: {err}");
                        e.reply_and_quote("消息保存失败，图片下载失败");
                        return;
                    }
                }
            }

            "reply" => {}

            _ => new_reply_msg.push(seg),
        }
    }

    let mut diy_map = diy_map.write();

    diy_map.push(DiyMsg {
        cmd: diy_msg,
        type_: msg_type,
        regex_cache,
        message: new_reply_msg,
    });

    e.reply_and_quote(match msg_type {
        DiyMsgType::Text => "文本消息已成功保存",
        DiyMsgType::Regex => "正则匹配消息已成功保存",
    });
}

async fn download_img<P: AsRef<Path>>(
    url: &str,
    dir_path: P,
) -> Result<String, Box<dyn std::error::Error>> {
    let dir_path = dir_path.as_ref();

    let response = reqwest::get(url).await?;

    if response.status().is_success() {
        // 如果不存在创建文件夹
        if tokio::fs::metadata(dir_path).await.is_err() {
            tokio::fs::create_dir(dir_path).await?;
        }
        // 字节流复制到文件
        let content = response.bytes().await?;
        let img_type = image::guess_format(&content)?;
        let typename = img_type.extensions_str()[0];

        let random_str = {
            let mut rng = rand::rng();
            let random_str: String = (0..7)
                .map(|_| rng.sample(rand::distr::Alphanumeric).to_string())
                .collect::<String>();
            random_str
        };

        let filename = format!(
            "{}-{}",
            chrono::Local::now().format("%Y-%m-%d-%H-%M-%S"),
            random_str
        );

        let filename = format!("{filename}.{typename}");

        let full_path = dir_path.join(filename);

        let mut dest = File::create(&full_path).await?;

        tokio::io::copy(&mut content.as_ref(), &mut dest).await?;

        log::info!("diy_msg: 成功保存图片");
        Ok(full_path.to_string_lossy().to_string())
    } else {
        log::error!("diy_msg: 请求失败");
        Err("diy_msg: 请求失败".into())
    }
}

async fn image_to_base64(path: &str) -> Option<String> {
    let mut file = File::open(path).await.ok()?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).await.ok()?;

    Some(STANDARD.encode(&buffer))
}

#[tokio::test]
async fn download_() {
    let url = "https://multimedia.nt.qq.com.cn/download?appid=1407&fileid=EhTDdS8aUl8YppSbYc5x6bis_haZpBimlTcg_woolKTo5OWBiwMyBHByb2RQgL2jAVoQBRXU51lYOf9HwThqs48H8Q&rkey=CAISKIo-QUl4cCNyemrYB3ewJV2x6avjXoI2rlsgM1mtbwjKbyWlSbyw4wM";

    download_img(url, "test").await.unwrap();
}

#[tokio::test]
async fn async_image_to_base64_() {
    use base64::engine::general_purpose::STANDARD;

    let image_path =
        "/home/threkork/work/kovi/my-bot/data/diy-msg/img/2025-01-20-15-28-55-dOuVAPkl.png";

    // 读取文件
    let mut file = File::open(image_path).await.unwrap();
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).await.unwrap();

    // 使用base64库编码
    let encoded = STANDARD.encode(&buffer);

    println!("{}", &encoded[..100])
}

#[test]
fn image_to_base64_() {
    use base64::engine::general_purpose::STANDARD;
    use std::fs::File;
    use std::io::Read;

    let image_path =
        "/home/threkork/work/kovi/my-bot/data/diy-msg/img/2025-01-20-15-28-55-dOuVAPkl.png";

    // 读取文件
    let mut file = File::open(image_path).unwrap();
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).unwrap();

    // 使用base64库编码
    let encoded = STANDARD.encode(&buffer);

    println!("{}", &encoded[..100])
}

#[test]
fn some_regex() {
    let re = regex::Regex::new("").unwrap();

    re.is_match("");
}
