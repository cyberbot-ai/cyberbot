#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    if args.get(1).map(String::as_str) == Some("--agents-probe") && args.len() == 2 {
        let statuses = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(cyberbot_lib::agents_probe());
        println!("{}", serde_json::to_string(&statuses).unwrap());
        return;
    }
    if args.get(1).map(String::as_str) == Some("--actions-smoke") && args.len() == 4 {
        let result = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(cyberbot_lib::actions_smoke(
                args[3].clone().into(),
                (args[2] != "none").then(|| args[2].clone()),
            ));
        match result {
            Ok(v) => {
                println!("{v}");
                if v["status"] != "completed" {
                    std::process::exit(1);
                }
            }
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(1);
            }
        }
        return;
    }
    if args.get(1).map(String::as_str) == Some("--models-smoke") && args.len() == 4 {
        let result = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(cyberbot_lib::models_smoke(
                args[3].clone().into(),
                args[2].clone(),
            ));
        match result {
            Ok(v) => println!("{v}"),
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(1);
            }
        }
        return;
    }
    if args.get(1).map(String::as_str) == Some("--activity-smoke") && args.len() == 3 {
        let result = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(cyberbot_lib::activity_smoke(args[2].clone().into()));
        match result {
            Ok(value) => println!("{value}"),
            Err(error) => {
                eprintln!("{error}");
                std::process::exit(1);
            }
        }
        return;
    }
    if args.get(1).map(String::as_str) == Some("--isolation-probe") {
        if args.len() != 7 {
            std::process::exit(2);
        }
        std::process::exit(cyberbot_lib::isolation::probe_main(&args[2..]));
    }
    if matches!(
        args.get(1).map(String::as_str),
        Some("--logs-smoke" | "--packages-smoke" | "--checks-smoke" | "--service-smoke")
    ) && args.len() == 4
    {
        let result = tokio::runtime::Runtime::new().unwrap().block_on(async {
            if args[1] == "--service-smoke" {
                cyberbot_lib::service_smoke(args[3].clone().into(), args[2].clone()).await
            } else if args[1] == "--checks-smoke" {
                cyberbot_lib::checks_smoke(args[3].clone().into(), args[2].clone()).await
            } else if args[1] == "--packages-smoke" {
                cyberbot_lib::packages_smoke(args[3].clone().into()).await
            } else {
                cyberbot_lib::logs_smoke(args[3].clone().into(), args[2].clone()).await
            }
        });
        match result {
            Ok(v) => {
                println!("{v}");
                std::process::exit(if v["status"] == "completed" { 0 } else { 1 });
            }
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(1);
            }
        }
    }
    if matches!(
        args.get(1).map(String::as_str),
        Some(
            "--agent-smoke"
                | "--agent-web-smoke"
                | "--agent-cancel-smoke"
                | "--auto-smoke"
                | "--auto-budget-smoke"
        )
    ) && args.len() == 4
    {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let result = runtime.block_on(cyberbot_lib::agent_smoke(
            args[3].clone().into(),
            args[2].clone(),
            args[1] == "--agent-cancel-smoke",
            match args[1].as_str() {
                "--auto-smoke" => Some(50000),
                "--auto-budget-smoke" => Some(1000),
                _ => None,
            },
            args[1] == "--agent-web-smoke",
        ));
        match result {
            Ok(v) => {
                println!("{v}");
                std::process::exit(
                    if v["status"]
                        == if args[1] == "--agent-cancel-smoke" {
                            "cancelled"
                        } else if args[1] == "--auto-budget-smoke" {
                            "budget_exceeded"
                        } else {
                            "completed"
                        }
                    {
                        0
                    } else {
                        1
                    },
                );
            }
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(1);
            }
        }
    }
    cyberbot_lib::run()
}
