/*
 * Copyright (C)2018 medozs and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.s
 */

import http from 'axios';
import * as sha256 from "fast-sha256";
import * as nacl from "tweetnacl-util";
import { Observable } from "rxjs/Observable";
import { Subscription } from "rxjs";
import { timer } from "rxjs/observable/timer";
// Observable class extensions
import "rxjs/add/observable/of";
// Observable operators
import "rxjs/add/operator/map";
import "rxjs/add/operator/do";
import "rxjs/add/operator/catch";
import "rxjs/add/operator/switchMap";
import "rxjs/add/operator/mergeMap";
import "rxjs/add/operator/filter";
import "rxjs/add/operator/debounceTime";
import "rxjs/add/operator/distinctUntilChanged";

//set process env variable
declare var global;
if (global!==undefined) {
    if(global["process"]===undefined) {global["process"] = {"env": {"NODE_ENV": "NS"}};}
    else if(global["process"]["env"]===undefined) {global["process"]["env"] = {"NODE_ENV": "NS"};}
    else if(global["process"]["env"]["NODE_ENV"]===undefined) {global["process"]["env"]["NODE_ENV"] = "NS";}
}

export class AuthService  {
    private accessToken: string;
    private refreshToken: string;
    private accessTimer: Subscription;
    private refreshTimer: Subscription;
    private _isAuthenticated: boolean;
    private formOptions:any = { headers: {'Content-Type':'application/x-www-form-urlencoded' }};
    private readonly REDIRECTDEFAULT = "app";
    private readonly DELAYTIMEDEFAULT = 10 * 1000;
    private readonly SCOPE = "openid+email+profile";

    private _config: Config;
    set config(config: Config) {
        this._config = config;
        if (!this._config.REDIRECT) {this._config.REDIRECT = this.REDIRECTDEFAULT; }
        if (!this._config.DELAYTIME) {this._config.DELAYTIME = this.DELAYTIMEDEFAULT; }
        if (!this._config.SCOPE) {this._config.SCOPE = this.SCOPE; }

    }
    get config() {
        return this._config;
    }

    public authenticated() {
        return this._isAuthenticated;
    }

    public getToken() {
        return this.accessToken;
    }

    public getUser(): Observable<Object> {
        return Observable.fromPromise(http.get(`${this.config.oauth2Config.userinfo_endpoint}`));
    }

    public login(): string {
        this.reset();
        return `${this.config.oauth2Config.authorization_endpoint}?client_id=${this.config.clientId}&redirect_uri=${this.config.REDIRECT}&response_type=code&scope=${this.config.SCOPE}&state=${this.config.state}&nonce=${this.config.nonce}`;
    }
    public loginPKCE(codeVerifier: string): string {
        this.reset();
        const codeChallenge =this.generateCodeChallenge(codeVerifier)
        return `${this.config.oauth2Config.authorization_endpoint}?client_id=${this.config.clientId}&redirect_uri=${this.config.REDIRECT}&response_type=code&scope=${this.config.SCOPE}&state=${this.config.state}&nonce=${this.config.nonce}&code_challenge=${codeChallenge}&code_challenge_method=S256`;
    }
    public logout(): string {
        this.reset();
        return  `${this.config.oauth2Config.end_session_endpoint}?redirect_uri=${this.config.REDIRECT}`;
    }
    public generateCodeChallenge(codeVerifier: string):string {    
        let rtn:string;
        const uintarray = nacl.decodeUTF8(codeVerifier);
        
        const hashedArray = sha256.hash(uintarray);
        let base64 = nacl.encodeBase64(hashedArray);
        base64 = base64.replace(/\+/g, '-');
        base64 = base64.replace(/\//g, '_');
        base64 = base64.replace(/=/g, '');
        rtn = base64;                
        return rtn;
    }

    private reset() {
        this.accessToken = null;
        this.refreshToken = null;
        this._isAuthenticated = false;
        if (this.refreshTimer) { this.refreshTimer.unsubscribe(); }
        if (this.accessTimer) { this.accessTimer.unsubscribe(); }
    }
    private renewToken (res) {
        this.accessTimer = timer((res.expires_in * 1000) - this.config.DELAYTIME).subscribe(() => {
            http.post(`${this.config.oauth2Config.token_endpoint}`,
            `client_id=${this.config.clientId}&client_secret=${this.config.clientSecret}&redirect_uri=${this.config.REDIRECT}&grant_type=refresh_token&refresh_token=${this.refreshToken}`,
            this.formOptions).then(res2 => <IToken> res2.data).then(res2 => {
                this.accessToken = res2.access_token;
                this.refreshToken = res2.refresh_token;
                this.renewToken(res2);
            }, (err) => this.login());
        }, (err) => console.error(err));
    }
    public init(code ?: string, codeVerifier?: string, options: IInitOptions = {}) {
        this.reset();

        let formOptions = Object.assign({}, this.formOptions);
        if (options.httpAuth) {
          formOptions.auth = {
            username: this.config.clientId,
            password: this.config.clientSecret,
          }
        }

        http.post(`${this.config.oauth2Config.token_endpoint}`,
        (code)?`client_id=${this.config.clientId}&client_secret=${this.config.clientSecret}&redirect_uri=${this.config.REDIRECT}&grant_type=authorization_code&code=${code}&code_verifier=${codeVerifier}`
        :`client_id=${this.config.clientId}&client_secret=${this.config.clientSecret}&grant_type=password&username=${this.config.username}&password=${this.config.password}`,
        formOptions).then(res => <IToken> res.data).then(res=> {
            this.accessToken = res.access_token;
            this.refreshToken = res.refresh_token;
            this._isAuthenticated = true;
            this.config.homeRoute();
            this.renewToken(res);
        }, (err) => console.error(err));
    }
}

export interface IInitOptions {
    httpAuth?: boolean
}

interface IToken {
    "access_token": string;
    "expires_in": string;
    "refresh_expires_in": string;
    "refresh_token": string;
    "token_type": string;
    "id_token": string;
    "not-before-policy": string;
    "session_state": string;
}

export interface Config {
    clientId: string;
    clientSecret: string;
    authRoute: () => void;
    homeRoute: ()=> void;
    REDIRECT?: string;
    DELAYTIME?: number;
    oauth2Config: OAuth2Config;
    username?: string;
    password?: string;
    SCOPE?: string;
    state?: string;
    nonce?: string;
}

export interface OAuth2Config {
    issuer: string;
    authorization_endpoint: string;
    token_endpoint: string;
    token_introspection_endpoint: string;
    userinfo_endpoint: string;
    end_session_endpoint: string;
    [x: string]: any;
}

